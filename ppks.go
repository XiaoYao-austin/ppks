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
	"github.com/tjfoc/gmsm/sm3"
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

type Pai struct {
	c, r1, r2 *(big.Int)
}

type PaiVector []Pai

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
// 		密文		ct{K,C}
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
	negrKy := new(big.Int).Neg(rKy)
	negrKy.Mod(negrKy, curve.Params().P)

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
// 		份额密文：	share
//		随机数：	ri
func ShareCal(targetPubKey *sm2.PublicKey, rB *CurvePoint, priv *sm2.PrivateKey) (*CipherText, *big.Int, error) {
	var share CipherText

	// 生成随机数ri
	curve := priv.Curve                             // 从公钥提取曲线
	ri, err := randFieldElement(curve, rand.Reader) // 从有限域中获得随机元素
	if err != nil {
		return &share, ri, err
	}

	// 计算左侧点K，riB
	share.K.Curve = priv.Curve
	share.K.X, share.K.Y = curve.ScalarBaseMult(ri.Bytes())

	// 计算-rKi，即-rBki，其中，Ki为己方公钥，ki为己方私钥
	rBkix, rBkiy := curve.ScalarMult(rB.X, rB.Y, priv.D.Bytes())
	rBkiy.Neg(rBkiy)
	rBkiy.Mod(rBkiy, curve.Params().P)

	// 计算riU
	riUx, riUy := curve.ScalarMult(targetPubKey.X, targetPubKey.Y, ri.Bytes())

	// 计算右侧点C，即-rKi+riU
	share.C.Curve = priv.Curve
	share.C.X, share.C.Y = curve.Add(rBkix, rBkiy, riUx, riUy)

	return &share, ri, nil
}

// ShareProofGen generate the proof of a share for the random nonce ri and the private-key priv.
// 份额计算证明生成: 使用计算份额生成的随机数ri和节点私钥priv，生成份额share的计算证明，并返回。
//
// 参数：
//		随机数：	ri
//		节点私钥：	priv
//		份额：		share
//		目标公钥：	targetPubKey
//		密文左侧点： rB
// 返回：
// 		证明pai：	c,r1,r2
func ShareProofGen(ri *big.Int, priv *sm2.PrivateKey, share *CipherText, targetPubKey *sm2.PublicKey, rB *CurvePoint) (*big.Int, *big.Int, *big.Int, error) {
	// share.K = ri*B ; priv.PublicKey = priv*B ;
	// targetPubKey*ri + (-rB*priv) = share.C
	// y1 = ri
	// y2 = priv.D
	// B = B
	// Y1 = riB = share.K
	// Y2 = priv.PublicKey
	// A1 = targetPubKey
	// A2 = -rB
	// A = share.C
	curve := priv.Curve
	var B CurvePoint
	B.Curve = curve
	B.X = curve.Params().Gx
	B.Y = curve.Params().Gy
	A2 := new(CurvePoint)
	A2.Curve = rB.Curve
	A2.X = new(big.Int).Set(rB.X)
	A2.Y = new(big.Int).Set(rB.Y)
	A2.Y.Neg(A2.Y)
	A2.Y.Mod(A2.Y, curve.Params().P)

	c, r1, r2, err := ProofGen(ri, priv.D, &B, &share.K, (*CurvePoint)(&priv.PublicKey), (*CurvePoint)(targetPubKey), A2, &share.C)
	if err != nil {
		return nil, nil, nil, err
	}

	return c, r1, r2, err
}

// ShareProofGenNoB generate the proof of a share for the random nonce ri and the private-key priv.
// 份额计算证明生成: 使用计算份额生成的随机数ri和节点私钥priv，生成份额share的计算证明，并返回。
//
// 参数：
//		随机数：	ri
//		节点私钥：	priv
//		份额：		share
//		目标公钥：	targetPubKey
//		密文左侧点： rB
// 返回：
// 		证明pai：	c,r1,r2
func ShareProofGenNoB(ri *big.Int, priv *sm2.PrivateKey, share *CipherText, targetPubKey *sm2.PublicKey, rB *CurvePoint) (*big.Int, *big.Int, *big.Int, error) {
	// share.K = ri*B ; priv.PublicKey = priv*B ;
	// targetPubKey*ri + (-rB*priv) = share.C
	// y1 = ri
	// y2 = priv.D
	// (B = B)
	// Y1 = riB = share.K
	// Y2 = priv.PublicKey
	// A1 = targetPubKey
	// A2 = -rB
	// A = share.C
	curve := priv.Curve
	A2 := new(CurvePoint)
	A2.Curve = rB.Curve
	A2.X = new(big.Int).Set(rB.X)
	A2.Y = new(big.Int).Set(rB.Y)
	A2.Y.Neg(A2.Y)
	A2.Y.Mod(A2.Y, curve.Params().P)

	c, r1, r2, err := ProofGenNoB(ri, priv.D, &share.K, (*CurvePoint)(&priv.PublicKey), (*CurvePoint)(targetPubKey), A2, &share.C)
	if err != nil {
		return nil, nil, nil, err
	}

	return c, r1, r2, err
}

// ShareProofVry verify the proof pai=(c,r1,r2) for the calculation of the share.
// 份额证明验证: 验证证明pai=(c,r1,r2)是否能够证明份额share是由随机数ri和节点私钥priv计算得来，即公开点(share,targetPubKey,rB)满足约束
//     {share.K = ri*B ; priv.PublicKey = priv*B ;
//      targetPubKey*ri + (-rB*priv) = share.C}，
// 并返回。
//
// 参数：
//		证明pai：	c,r1,r2
//		份额：		share
//		节点公钥：	nodePubKey
//		目标公钥：	targetPubKey
//		密文左侧点： rB
// 返回：
// 		验证结果：	bool
func ShareProofVry(c, r1, r2 *big.Int, share *CipherText, nodePubKey, targetPubKey *sm2.PublicKey, rB *CurvePoint) (bool, error) {
	// share.K = ri*B ; priv.PublicKey = priv*B ;
	// targetPubKey*ri + (-rB*priv) = share.C
	// c,r1,r2 = c,r1,r2
	// B = B
	// Y1 = riB = share.K
	// Y2 = nodePubKey
	// A1 = targetPubKey
	// A2 = -rB
	// A = share.C
	curve := targetPubKey.Curve
	var B CurvePoint
	B.Curve = curve
	B.X = curve.Params().Gx
	B.Y = curve.Params().Gy
	A2 := new(CurvePoint)
	A2.Curve = rB.Curve
	A2.X = new(big.Int).Set(rB.X)
	A2.Y = new(big.Int).Set(rB.Y)
	A2.Y.Neg(A2.Y)
	A2.Y.Mod(A2.Y, curve.Params().P)

	flag, err := ProofVrf(c, r1, r2, &B, &share.K, (*CurvePoint)(nodePubKey), (*CurvePoint)(targetPubKey), A2, &share.C)
	if err != nil {
		return false, err
	}

	return flag, err
}

// ShareProofVryNoB verify the proof pai=(c,r1,r2) for the calculation of the share.
// 份额证明验证: 验证证明pai=(c,r1,r2)是否能够证明份额share是由随机数ri和节点私钥priv计算得来，即公开点(share,targetPubKey,rB)满足约束
//     {share.K = ri*B ; priv.PublicKey = priv*B ;
//      targetPubKey*ri + (-rB*priv) = share.C}，
// 并返回。
//
// 参数：
//		证明pai：	c,r1,r2
//		份额：		share
//		节点公钥：	nodePubKey
//		目标公钥：	targetPubKey
//		密文左侧点： rB
// 返回：
// 		验证结果：	bool
func ShareProofVryNoB(c, r1, r2 *big.Int, share *CipherText, nodePubKey, targetPubKey *sm2.PublicKey, rB *CurvePoint) (bool, error) {
	// share.K = ri*B ; priv.PublicKey = priv*B ;
	// targetPubKey*ri + (-rB*priv) = share.C
	// c,r1,r2 = c,r1,r2
	// (B = B)
	// Y1 = riB = share.K
	// Y2 = nodePubKey
	// A1 = targetPubKey
	// A2 = -rB
	// A = share.C
	curve := targetPubKey.Curve
	A2 := new(CurvePoint)
	A2.Curve = rB.Curve
	A2.X = new(big.Int).Set(rB.X)
	A2.Y = new(big.Int).Set(rB.Y)
	A2.Y.Neg(A2.Y)
	A2.Y.Mod(A2.Y, curve.Params().P)

	flag, err := ProofVrfNoB(c, r1, r2, &share.K, (*CurvePoint)(nodePubKey), (*CurvePoint)(targetPubKey), A2, &share.C)
	if err != nil {
		return false, err
	}

	return flag, err
}

// ProofGen generate the proof for (y1,y2) with constraints {Y1=y1*B,Y2=y2*B,A1*y1+A2*y2=A}.
// 零知识证明生成: 为（y1,y2）生成满足约束
//     {Y1=y1*B,Y2=y2*B,A1*y1+A2*y2=A}
// 的证明pai=(c,r1,r2)，并返回。
//
// 参数：
//		标量：	y1,y2
//		点：B,Y1,Y2,A1,A2,A
// 返回：
// 		证明:	c,r1,r2
func ProofGen(y1, y2 *big.Int, B, Y1, Y2, A1, A2, A *CurvePoint) (*big.Int, *big.Int, *big.Int, error) {
	// 生成两个随机数v1,v2
	curve := Y1.Curve                               // 从公钥提取曲线
	v1, err := randFieldElement(curve, rand.Reader) // 从有限域中获得随机元素
	if err != nil {
		return nil, nil, nil, err
	}
	v2, err := randFieldElement(curve, rand.Reader) // 从有限域中获得随机元素
	if err != nil {
		return nil, nil, nil, err
	}

	// 计算承诺值：T1=v1*B, T2=v2*B, T3=v1*A1+v2*A2
	var T1, T2, T3 CurvePoint
	T1.Curve = curve
	T1.X, T1.Y = curve.ScalarMult(B.X, B.Y, v1.Bytes())
	T2.Curve = curve
	T2.X, T2.Y = curve.ScalarMult(B.X, B.Y, v2.Bytes())
	T3.Curve = curve
	vA1x, vA1y := curve.ScalarMult(A1.X, A1.Y, v1.Bytes())
	vA2x, vA2y := curve.ScalarMult(A2.X, A2.Y, v2.Bytes())
	T3.X, T3.Y = curve.Add(vA1x, vA1y, vA2x, vA2y)

	// 计算挑战：c=H(B,Y1,Y2,A1,A2,A,T1,T2,T3)
	h := sm3.New()
	h.Write(B.X.Bytes())
	h.Write(B.Y.Bytes())
	h.Write(Y1.X.Bytes())
	h.Write(Y1.Y.Bytes())
	h.Write(Y2.X.Bytes())
	h.Write(Y2.Y.Bytes())
	h.Write(A1.X.Bytes())
	h.Write(A1.Y.Bytes())
	h.Write(A2.X.Bytes())
	h.Write(A2.Y.Bytes())
	h.Write(A.X.Bytes())
	h.Write(A.Y.Bytes())
	h.Write(T1.X.Bytes())
	h.Write(T1.Y.Bytes())
	h.Write(T2.X.Bytes())
	h.Write(T2.Y.Bytes())
	h.Write(T3.X.Bytes())
	h.Write(T3.Y.Bytes())
	c := new(big.Int).SetBytes(h.Sum(nil)[:32])

	// 计算应答：r1=v1-c*y1, r2=v2-c*y2
	r1 := new(big.Int).Mul(c, y1)
	r1.Mod(r1, curve.Params().N)
	r1 = new(big.Int).Sub(v1, r1)
	r1.Mod(r1, curve.Params().N)

	r2 := new(big.Int).Mul(c, y2)
	r2.Mod(r2, curve.Params().N)
	r2.Sub(v2, r2)
	r2.Mod(r2, curve.Params().N)

	return c, r1, r2, nil
}

// ProofGenNoB generate the proof for (y1,y2) with constraints {Y1=y1*B,Y2=y2*B,A1*y1+A2*y2=A}.
// 零知识证明生成: 为（y1,y2）生成满足约束
//     {Y1=y1*B,Y2=y2*B,A1*y1+A2*y2=A}
// 的证明pai=(c,r1,r2)，并返回。
//
// 参数：
//		标量：	y1,y2
//		点：Y1,Y2,A1,A2,A
// 返回：
// 		证明:	c,r1,r2
func ProofGenNoB(y1, y2 *big.Int, Y1, Y2, A1, A2, A *CurvePoint) (*big.Int, *big.Int, *big.Int, error) {
	// 生成两个随机数v1,v2
	curve := Y1.Curve                               // 从公钥提取曲线
	v1, err := randFieldElement(curve, rand.Reader) // 从有限域中获得随机元素
	if err != nil {
		return nil, nil, nil, err
	}
	v2, err := randFieldElement(curve, rand.Reader) // 从有限域中获得随机元素
	if err != nil {
		return nil, nil, nil, err
	}

	// 计算承诺值：T1=v1*B, T2=v2*B, T3=v1*A1+v2*A2
	var T1, T2, T3 CurvePoint
	T1.Curve = curve
	T1.X, T1.Y = curve.ScalarBaseMult(v1.Bytes())
	T2.Curve = curve
	T2.X, T2.Y = curve.ScalarBaseMult(v2.Bytes())
	T3.Curve = curve
	vA1x, vA1y := curve.ScalarMult(A1.X, A1.Y, v1.Bytes())
	vA2x, vA2y := curve.ScalarMult(A2.X, A2.Y, v2.Bytes())
	T3.X, T3.Y = curve.Add(vA1x, vA1y, vA2x, vA2y)

	// 计算挑战：c=H(B,Y1,Y2,A1,A2,A,T1,T2,T3)
	h := sm3.New()
	h.Write(curve.Params().Gx.Bytes())
	h.Write(curve.Params().Gy.Bytes())
	h.Write(Y1.X.Bytes())
	h.Write(Y1.Y.Bytes())
	h.Write(Y2.X.Bytes())
	h.Write(Y2.Y.Bytes())
	h.Write(A1.X.Bytes())
	h.Write(A1.Y.Bytes())
	h.Write(A2.X.Bytes())
	h.Write(A2.Y.Bytes())
	h.Write(A.X.Bytes())
	h.Write(A.Y.Bytes())
	h.Write(T1.X.Bytes())
	h.Write(T1.Y.Bytes())
	h.Write(T2.X.Bytes())
	h.Write(T2.Y.Bytes())
	h.Write(T3.X.Bytes())
	h.Write(T3.Y.Bytes())
	c := new(big.Int).SetBytes(h.Sum(nil)[:32])

	// 计算应答：r1=v1-c*y1, r2=v2-c*y2
	r1 := new(big.Int).Mul(c, y1)
	r1.Mod(r1, curve.Params().N)
	r1 = new(big.Int).Sub(v1, r1)
	r1.Mod(r1, curve.Params().N)

	r2 := new(big.Int).Mul(c, y2)
	r2.Mod(r2, curve.Params().N)
	r2.Sub(v2, r2)
	r2.Mod(r2, curve.Params().N)

	return c, r1, r2, nil
}

// ProofVrf verify the proof pai=(c,r1,r2) with public points (B,Y1,Y2,A1,A2,A).
// 零知识证明验证: 验证证明pai=(c,r1,r2)是否能够证明公开点(B,Y1,Y2,A1,A2,A)满足约束
//     {Y1=y1*B,Y2=y2*B,A1*y1+A2*y2=A}，
// 并返回。
//
// 参数：
//		证明：	c,r1,r2
//		点：B,Y1,Y2,A1,A2,A
// 返回：
// 		份额密文
func ProofVrf(c, r1, r2 *big.Int, B, Y1, Y2, A1, A2, A *CurvePoint) (bool, error) {
	curve := Y1.Curve

	// 重构承诺：T1'=r1*B+c*Y1, T2'=r2*B+c*Y2, T3'=r1*A1+r2*A2+c*A
	// 下文Ti' 用Ti指代
	var T1, T2, T3 CurvePoint

	T1.Curve = curve
	rB1x, rB1y := curve.ScalarMult(B.X, B.Y, r1.Bytes())
	cY1x, cY1y := curve.ScalarMult(Y1.X, Y1.Y, c.Bytes())
	T1.X, T1.Y = curve.Add(rB1x, rB1y, cY1x, cY1y)

	T2.Curve = curve
	rB2x, rB2y := curve.ScalarMult(B.X, B.Y, r2.Bytes())
	cY2x, cY2y := curve.ScalarMult(Y2.X, Y2.Y, c.Bytes())
	T2.X, T2.Y = curve.Add(rB2x, rB2y, cY2x, cY2y)

	T3.Curve = curve
	rA1x, rA1y := curve.ScalarMult(A1.X, A1.Y, r1.Bytes())
	rA2x, rA2y := curve.ScalarMult(A2.X, A2.Y, r2.Bytes())
	cAx, cAy := curve.ScalarMult(A.X, A.Y, c.Bytes())
	T3.X, T3.Y = curve.Add(rA1x, rA1y, rA2x, rA2y)
	T3.X, T3.Y = curve.Add(T3.X, T3.Y, cAx, cAy)

	// 计算新的挑战值：c'=H(B,Y1,Y2,A1,A2,A,T1',T2',T3')
	// 如上，c'用c_new代替
	h := sm3.New()
	h.Write(B.X.Bytes())
	h.Write(B.Y.Bytes())
	h.Write(Y1.X.Bytes())
	h.Write(Y1.Y.Bytes())
	h.Write(Y2.X.Bytes())
	h.Write(Y2.Y.Bytes())
	h.Write(A1.X.Bytes())
	h.Write(A1.Y.Bytes())
	h.Write(A2.X.Bytes())
	h.Write(A2.Y.Bytes())
	h.Write(A.X.Bytes())
	h.Write(A.Y.Bytes())
	h.Write(T1.X.Bytes())
	h.Write(T1.Y.Bytes())
	h.Write(T2.X.Bytes())
	h.Write(T2.Y.Bytes())
	h.Write(T3.X.Bytes())
	h.Write(T3.Y.Bytes())
	c_new := new(big.Int).SetBytes(h.Sum(nil)[:32])

	// 检查一致性：c?=c'
	if 0 == c.Cmp(c_new) {
		return true, nil
	} else {
		return false, nil
	}
}

// ProofVrfNoB verify the proof pai=(c,r1,r2) with public points (Y1,Y2,A1,A2,A).
// 零知识证明验证: 验证证明pai=(c,r1,r2)是否能够证明公开点(Y1,Y2,A1,A2,A)满足约束
//     {Y1=y1*B,Y2=y2*B,A1*y1+A2*y2=A}，
// 并返回。
//
// 参数：
//		证明：	c,r1,r2
//		点：Y1,Y2,A1,A2,A
// 返回：
// 		份额密文
func ProofVrfNoB(c, r1, r2 *big.Int, Y1, Y2, A1, A2, A *CurvePoint) (bool, error) {
	curve := Y1.Curve

	// 重构承诺：T1'=r1*B+c*Y1, T2'=r2*B+c*Y2, T3'=r1*A1+r2*A2+c*A
	// 下文Ti' 用Ti指代
	var T1, T2, T3 CurvePoint

	T1.Curve = curve
	r1Bx, r1By := curve.ScalarBaseMult(r1.Bytes())
	cY1x, cY1y := curve.ScalarMult(Y1.X, Y1.Y, c.Bytes())
	T1.X, T1.Y = curve.Add(r1Bx, r1By, cY1x, cY1y)

	T2.Curve = curve
	rB2x, rB2y := curve.ScalarBaseMult(r2.Bytes())
	cY2x, cY2y := curve.ScalarMult(Y2.X, Y2.Y, c.Bytes())
	T2.X, T2.Y = curve.Add(rB2x, rB2y, cY2x, cY2y)

	T3.Curve = curve
	rA1x, rA1y := curve.ScalarMult(A1.X, A1.Y, r1.Bytes())
	rA2x, rA2y := curve.ScalarMult(A2.X, A2.Y, r2.Bytes())
	cAx, cAy := curve.ScalarMult(A.X, A.Y, c.Bytes())
	T3.X, T3.Y = curve.Add(rA1x, rA1y, rA2x, rA2y)
	T3.X, T3.Y = curve.Add(T3.X, T3.Y, cAx, cAy)

	// 计算新的挑战值：c'=H(B,Y1,Y2,A1,A2,A,T1',T2',T3')
	// 如上，c'用c_new代替
	h := sm3.New()
	h.Write(curve.Params().Gx.Bytes())
	h.Write(curve.Params().Gy.Bytes())
	h.Write(Y1.X.Bytes())
	h.Write(Y1.Y.Bytes())
	h.Write(Y2.X.Bytes())
	h.Write(Y2.Y.Bytes())
	h.Write(A1.X.Bytes())
	h.Write(A1.Y.Bytes())
	h.Write(A2.X.Bytes())
	h.Write(A2.Y.Bytes())
	h.Write(A.X.Bytes())
	h.Write(A.Y.Bytes())
	h.Write(T1.X.Bytes())
	h.Write(T1.Y.Bytes())
	h.Write(T2.X.Bytes())
	h.Write(T2.Y.Bytes())
	h.Write(T3.X.Bytes())
	h.Write(T3.Y.Bytes())
	c_new := new(big.Int).SetBytes(h.Sum(nil)[:32])

	// 检查一致性：c?=c'
	if 0 == c.Cmp(c_new) {
		return true, nil
	} else {
		return false, nil
	}
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

// randFieldElement generates a random k in Z_curve.N and returns.
// 在椭圆曲线对生成元点G的秩N内生成随机数并返回。
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
