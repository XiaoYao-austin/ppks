/*
Copyright 2021 XiaoYao(Beijing Institute of Technology)
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ppks Practical Parallel Key Switch
package ppks

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

/*
public&private key struct in lib sm2.
引用库sm2中公私钥结构定义：

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}
*/

// CurvePoint 曲线上的点
type CurvePoint sm2.PublicKey

// PointVector 曲线点向量
type PointVector []CurvePoint

// CipherText is an ElGamal encrypted point.
// 密文，基于群的ElGamal加密文本，形式为群上点对。
type CipherText struct {
	K, C CurvePoint
}

// CipherVector is a slice of ElGamal encrypted points.
// 密文向量，基于群的ElGamal密文slice。
type CipherVector []CipherText

// GenPrivKey generates a private key at random.
// 生成私钥：随机生成一个私钥并返回。
//
// 参数：
//
// 返回：
// 		私钥
func GenPrivKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// GetPubKey returns the public key from priv.
// 获取公钥：从私钥priv中取出公钥。
//
// 参数：
//		私钥	priv
// 返回：
// 		公钥
func GetPubKey(priv *sm2.PrivateKey) *sm2.PublicKey {
	return &priv.PublicKey
}

// GenPoint generates a curve point at random.
// 生成点：随机生成一个点并返回。
//
// 参数：
//
// 返回：
// 		点
func GenPoint() *CurvePoint {
	d, err := GenPrivKey()
	if err != nil {
		log.Fatal(err)
	}

	return (*CurvePoint)(&d.PublicKey)
}

// CollPrivKey returns the addition of the private keys in privs.
// 聚合私钥：加和privs中的私钥，并返回。
//
// 参数：
//		私钥slice	privs
// 返回：
// 		聚合私钥
func CollPrivKey(privs []sm2.PrivateKey) *sm2.PrivateKey {

	// 返回集合公钥
	collPrivKey := privs[0]

	// 私钥&公钥变量
	collPriv, _ := new(big.Int).SetString("0", 16)
	// pubKeys := make([]sm2.PublicKey, len(privs))

	// 遍历私钥组
	for i := 0; i < len(privs); i++ {
		// 累加私钥
		collPriv.Add(collPriv, privs[i].D)
		if collPriv.Cmp(collPrivKey.Curve.Params().N) >= 0 {
			collPriv.Mod(collPriv, collPrivKey.Curve.Params().N)
		}
		// 赋值公钥组
		// pubKeys[i] = *(GetPubKey(&privs[i]))
	}

	// 分别赋值私钥&公钥
	collPrivKey.D = collPriv
	// collPrivKey.PublicKey = *CollPubKey(pubKeys)
	collPrivKey.PublicKey.X, collPrivKey.PublicKey.Y = collPrivKey.PublicKey.Curve.ScalarBaseMult(collPrivKey.D.Bytes())

	return &collPrivKey
}

// CollPubKey returns the addition of the public keys in pubs.
// 聚合公钥：加和pubs中的公钥，并返回。
//
// 参数：
//		公钥slice	pubs
// 返回：
// 		聚合公钥
func CollPubKey(pubs []sm2.PublicKey) *sm2.PublicKey {
	collPubKey := pubs[0]
	curve := collPubKey.Curve
	for i := 1; i < len(pubs); i++ {
		collPubKey.X, collPubKey.Y = curve.Add(collPubKey.X, collPubKey.Y, pubs[i].X, pubs[i].Y)
	}
	return &collPubKey
}

// PointEncrypt encrypts D with pub and returns the ciphertext.
// 点加密：使用公钥加密点D，返回密文。
// 本项目中使用点D的指定坐标来作为对称密钥（暂定为横坐标）。
//
// 参数：
//		公钥		pub
//		待加密点	D
// 返回：
// 		密文
func PointEncrypt(pub *sm2.PublicKey, D *CurvePoint) (*CipherText, error) {
	var ct CipherText

	// 从公钥提取曲线
	curve := pub.Curve
	// 从有限域中获得随机元素
	r, err := randFieldElement(curve, rand.Reader)
	if err != nil {
		return &ct, err
	}

	// 随机数数乘生成元，生成密文左侧点K，rB
	ct.K.Curve = curve
	ct.K.X, ct.K.Y = curve.ScalarBaseMult(r.Bytes())

	// 随机数乘公钥得到点rK
	rKx, rKy := curve.ScalarMult(pub.X, pub.Y, r.Bytes())

	// 待加密点与点rK相加，得到右侧点，ct.C
	ct.C.Curve = curve
	ct.C.X, ct.C.Y = curve.Add(rKx, rKy, D.X, D.Y)

	return &ct, nil
}

// PointDecrypt decrypts ct with priv and returns the resulting curve point.
// 点解密：使用私钥priv解密密文ct，返回结果点。
// 本项目中使用其中指定坐标来作为对称密钥（暂定为横坐标）。
//
// 参数：
//		密文		ct
//		私钥		priv
// 返回：
// 		明文点
func PointDecrypt(ct *CipherText, priv *sm2.PrivateKey) (*CurvePoint, error) {

	curve := priv.Curve

	// 原算法
	////////////////////////////////////////////////////////////////////////
	// 私钥数乘左侧点K(rB)，得到点rK
	rKx, rKy := curve.ScalarMult(ct.K.X, ct.K.Y, priv.D.Bytes())

	// 求点-rK，纵坐标取负值
	negrKy := rKy.Neg(rKy)

	// 密文右侧点C减去rK(加上负rK)，得到密文点
	var D CurvePoint
	D.Curve = curve
	D.X, D.Y = priv.Curve.Add(ct.C.X, ct.C.Y, rKx, negrKy)
	////////////////////////////////////////////////////////////////////////

	// 新算法
	////////////////////////////////////////////////////////////////////////
	// // 计算私钥模n的负数，-priv
	// negPriv := priv.D.Neg(priv.D)
	// negPriv.Mod(negPriv, curve.Params().N)

	// // 计算点-rK，即rB*(-priv)
	// negrKx, negrKy := curve.ScalarMult(ct.K.X, ct.K.Y, negPriv.Bytes())

	// // 密文右侧点C加上点-rK，计算明文点D
	// var D CurvePoint
	// D.Curve = curve
	// D.X, D.Y = curve.Add(ct.C.X, ct.C.Y, negrKx, negrKy)
	////////////////////////////////////////////////////////////////////////

	return &D, nil
}

// ShareCal calculates the share related with rB(left point K in ciphertext)
// for targetPubKey with priv.
// 份额计算: 使用私钥priv，为目标公钥targetPubKey计算关于点rB（一份密文的左侧点K）的份额，并返回。
//
// 参数：
//		目标公钥	pub
//		密文左侧点	rB
//		私钥		priv
// 返回：
// 		份额密文
func ShareCal(targetPubKey *sm2.PublicKey, rB *CurvePoint, priv *sm2.PrivateKey) (*CipherText, error) {
	var share CipherText

	// 生成随机数ri
	curve := priv.Curve                             // 从公钥提取曲线
	ri, err := randFieldElement(curve, rand.Reader) // 从有限域中获得随机元素
	if err != nil {
		return &share, err
	}

	// 计算左侧点K，riB
	share.K.Curve = priv.Curve
	share.K.X, share.K.Y = curve.ScalarBaseMult(ri.Bytes())

	// 计算-rKi，即-rBki，其中，Ki为己方公钥，ki为己方私钥
	rBkix, rBkiy := curve.ScalarMult(rB.X, rB.Y, priv.D.Bytes())
	rBkiy.Neg(rBkiy)

	// 计算riU
	riUx, riUy := curve.ScalarMult(targetPubKey.X, targetPubKey.Y, ri.Bytes())

	// 计算右侧点C，即-rKi+riU
	share.C.Curve = priv.Curve
	share.C.X, share.C.Y = curve.Add(rBkix, rBkiy, riUx, riUy)

	return &share, nil
}

// ShareReplace uses shares to convert rct(raw ciphertext) to a new ciphertext.
// 份额置换：使用份额置换原密文为新密文，并返回。
//
// 参数：
//		份额slice	shares
//		密文原文	rct
// 返回：
// 		新密文
func ShareReplace(shares *CipherVector, rct *CipherText) (*CipherText, error) {
	curve := rct.K.Curve

	// 检查置换份额数量
	lens := len(*shares)
	// 聚合份额至sigma
	sigma := (*shares)[0]
	for i := 1; i < lens; i++ {
		sigma.K.X, sigma.K.Y = curve.Add(sigma.K.X, sigma.K.Y, (*shares)[i].K.X, (*shares)[i].K.Y)
		sigma.C.X, sigma.C.Y = curve.Add(sigma.C.X, sigma.C.Y, (*shares)[i].C.X, (*shares)[i].C.Y)
	}

	// 通过sigma置换rct得到目标ct
	ct := sigma
	ct.C.X, ct.C.Y = curve.Add(sigma.C.X, sigma.C.Y, rct.C.X, rct.C.Y)

	return &ct, nil
}

var one = new(big.Int).SetInt64(1)

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}
