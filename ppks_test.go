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

package ppks

import (
	"fmt"
	"log"
	"math/big"
	"reflect"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestGenPrivKey(t *testing.T) {
	fmt.Println()

	priv, err := GenPrivKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}

	vr := priv
	fmt.Println("type of var: ", reflect.TypeOf(vr))
	fmt.Println("value of var: ", vr)

	fmt.Println()
}

func TestGetPubKey(t *testing.T) {
	fmt.Println()

	priv, err := GenPrivKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	pubKey := GetPubKey(priv)

	vr := pubKey
	fmt.Println("name of var: GetPubKey(priv)")
	fmt.Println("type of var: ", reflect.TypeOf(vr))
	fmt.Println("value of var: ", vr)

	vr1 := priv.PublicKey
	fmt.Println("name of var: priv.PublicKey")
	fmt.Println("type of var: ", reflect.TypeOf(vr1))
	fmt.Println("value of var: ", vr1)

	fmt.Println()
}
func TestGenPoint(t *testing.T) {
	// 集成于TestPointEncrypt&TestPointDecrypt，不单独测试
}
func TestCollPrivKey(t *testing.T) {
	fmt.Println()

	////////////////////////
	// 聚合私钥数量//////////
	lens := 10
	////////////////////////

	privKeys := make([]sm2.PrivateKey, lens)
	pubKeys := make([]sm2.PublicKey, lens)

	for i := 0; i < lens; i++ {
		priv, err := GenPrivKey() // 生成第i个密钥对
		if err != nil {
			log.Fatal(err)
		}

		// 填充私钥
		privKeys[i] = *priv
		pubKeys[i] = *(GetPubKey(priv))
	}

	// 累加私钥
	collPrivKey := CollPrivKey(privKeys)
	collPubKey := CollPubKey(pubKeys)

	D := GenPoint()

	ct, _ := PointEncrypt(collPubKey, D)

	dct, _ := PointDecrypt(ct, collPrivKey)

	vr := collPrivKey
	fmt.Println("调用集合私钥函数得到的私钥")
	fmt.Println("type of var: ", reflect.TypeOf(vr))
	fmt.Println("value of var: ", vr)

	vr1 := collPubKey
	fmt.Println("调用集合公钥函数得到的公钥")
	fmt.Println("type of var: ", reflect.TypeOf(vr1))
	fmt.Println("value of var: ", vr1)

	vr2 := D
	fmt.Println("加密点D")
	fmt.Println("type of var: ", reflect.TypeOf(vr2))
	fmt.Println("value of var: ", vr2)

	vr3 := ct
	fmt.Println("用集合公钥加密的密文")
	fmt.Println("type of var: ", reflect.TypeOf(vr3))
	fmt.Println("value of var: ", vr3)

	vr4 := dct
	fmt.Println("用集合私钥解密的明文")
	fmt.Println("type of var: ", reflect.TypeOf(vr4))
	fmt.Println("value of var: ", vr4)

	fmt.Println()
}

func TestCollPubKey(t *testing.T) {
	fmt.Println()

	////////////////////////
	// 聚合公钥数量//////////
	lens := 10
	////////////////////////

	collPriv, _ := new(big.Int).SetString("0", 16)
	collPubKey := make([]sm2.PublicKey, lens)

	for i := 0; i < lens; i++ {
		priv, err := GenPrivKey() // 生成第i个密钥对
		if err != nil {
			log.Fatal(err)
		}

		// 累加私钥
		collPriv.Add(collPriv, priv.D)
		if collPriv.Cmp(priv.Curve.Params().N) >= 0 {
			collPriv.Mod(collPriv, priv.Curve.Params().N)
		}
		// 填充公钥
		collPubKey[i] = *(GetPubKey(priv))
		// collPubKey.X, collPubKey.Y = curve.Add(collPubKey.X, collPubKey.Y, priv.PublicKey.X, priv.PublicKey.Y)
	}

	// 1018
	// 累加公钥
	cPubKey := CollPubKey(collPubKey)

	// 从累加私钥数乘基点生成新公钥
	var newPubKey sm2.PublicKey
	newPubKey.Curve = collPubKey[0].Curve
	newPubKey.X, newPubKey.Y = newPubKey.Curve.ScalarBaseMult(collPriv.Bytes())

	vr := collPriv
	fmt.Println("type of var: ", reflect.TypeOf(vr))
	fmt.Println("value of var: ", vr)

	vr1 := *cPubKey
	fmt.Println("type of var: ", reflect.TypeOf(vr1))
	fmt.Println("value of var: ", vr1)

	vr2 := newPubKey
	fmt.Println("type of var: ", reflect.TypeOf(vr2))
	fmt.Println("value of var: ", vr2)

	if 0 == vr1.X.Cmp(vr2.X) && 0 == vr1.Y.Cmp(vr2.Y) {
		fmt.Println("Eqal")
	} else {
		fmt.Println("not Eqal")
	}

	fmt.Println()
}
func TestPointEncrypt(t *testing.T) {
	fmt.Println()

	priv, err := GenPrivKey() // 生成加密使用的密钥对
	if err != nil {
		log.Fatal(err)
	}
	pubKey := GetPubKey(priv)

	// 生成待加密的点
	D := GenPoint()

	ct, _ := PointEncrypt(pubKey, D)

	vr := ct
	fmt.Println("type of var: ", reflect.TypeOf(vr))
	fmt.Println("value of var: ", vr)

	fmt.Println()
}
func TestPointDecrypt(t *testing.T) {
	fmt.Println()

	priv, err := GenPrivKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	pubKey := GetPubKey(priv)

	D := GenPoint()

	ct, _ := PointEncrypt(pubKey, D)

	dct, _ := PointDecrypt(ct, priv)

	vr := D
	fmt.Println("name of var: D")
	fmt.Println("type of var: ", reflect.TypeOf(vr))
	fmt.Println("value of var: ", vr)
	vr1 := ct
	fmt.Println("name of var: ct")
	fmt.Println("type of var: ", reflect.TypeOf(vr1))
	fmt.Println("value of var: ", vr1)
	vr2 := dct
	fmt.Println("name of var: dct")
	fmt.Println("type of var: ", reflect.TypeOf(vr2))
	fmt.Println("value of var: ", vr2)

	fmt.Println()
}

func TestShareCal(t *testing.T) {
	// 集成于TestWorkFlow()，不单独测试
}

func TestShareProofGen_Vrf_NoB(t *testing.T) {
	// 实验次数
	count := 10
	NoB := false

	for i := 0; i < count; i++ {
		// 生成私钥
		priv, err := GenPrivKey()
		if err != nil {
			log.Fatal(err)
		}

		// 生成目标公钥
		targetPubKey := GenPoint()

		// 生成密文左侧点
		rB := GenPoint()

		// 计算share
		share, ri, err := ShareCal((*sm2.PublicKey)(targetPubKey), rB, priv)
		if err != nil {
			log.Fatal(err)
		}

		if NoB {
			// 计算证明
			c, r1, r2, err := ShareProofGenNoB(ri, priv, share, (*sm2.PublicKey)(targetPubKey), rB)

			// 计算证明验证结果
			flag, err := ShareProofVryNoB(c, r1, r2, share, &priv.PublicKey, (*sm2.PublicKey)(targetPubKey), rB)
			if err != nil {
				log.Fatal(err)
			}
			if false == flag {
				fmt.Println()
				fmt.Println(i, "th value of var: ", flag)
				fmt.Println()
			} else {
				fmt.Println("   c:", c)
				// fmt.Println("  r1:", r1)
				// fmt.Println("  r2:", r2)
				// fmt.Println("flag:", flag)
			}
		} else {
			// 计算证明
			c, r1, r2, err := ShareProofGen(ri, priv, share, (*sm2.PublicKey)(targetPubKey), rB)

			// 计算证明验证结果
			flag, err := ShareProofVry(c, r1, r2, share, &priv.PublicKey, (*sm2.PublicKey)(targetPubKey), rB)
			if err != nil {
				log.Fatal(err)
			}
			if false == flag {
				fmt.Println()
				fmt.Println(i, "th value of var: ", flag)
				fmt.Println()
			} else {
				fmt.Println("   c:", c)
				// fmt.Println("  r1:", r1)
				// fmt.Println("  r2:", r2)
				// fmt.Println("flag:", flag)
			}
		}

	}
}

func TestProofGen_Vrf_NoB(t *testing.T) {
	count := 10
	NoB := true

	for i := 0; i < count; i++ {
		// 生成 y1,Y1,y2,Y2: Y1=y1*B=y1.PublicKey,Y2=y2*B=y2.PublicKey
		y1, err := GenPrivKey()
		if err != nil {
			log.Fatal(err)
		}
		y2, err := GenPrivKey()
		if err != nil {
			log.Fatal(err)
		}

		// 生成A1,A2
		A1 := GenPoint()
		A2 := GenPoint()

		// 生成A=A1*y1+A2*y2
		var A CurvePoint
		A.Curve = A1.Curve
		Ay1x, Ay1y := A1.Curve.ScalarMult(A1.X, A1.Y, y1.D.Bytes())
		Ay2x, Ay2y := A2.Curve.ScalarMult(A2.X, A2.Y, y2.D.Bytes())
		A.X, A.Y = A.Curve.Add(Ay1x, Ay1y, Ay2x, Ay2y)

		if NoB {
			// 计算证明
			c, r1, r2, err := ProofGenNoB(y1.D, y2.D, (*CurvePoint)(&y1.PublicKey), (*CurvePoint)(&y2.PublicKey), A1, A2, &A)
			if err != nil {
				log.Fatal(err)
			}

			// 计算验证结果
			flag, err := ProofVrfNoB(c, r1, r2, (*CurvePoint)(&y1.PublicKey), (*CurvePoint)(&y2.PublicKey), A1, A2, &A)
			if err != nil {
				log.Fatal(err)
			}
			if false == flag {
				fmt.Println(i, "th value of var: ", flag)
			}
		} else {
			// 生成B
			var B CurvePoint
			B.Curve = y1.Curve
			B.X = B.Curve.Params().Gx
			B.Y = B.Curve.Params().Gy

			// 计算证明
			c, r1, r2, err := ProofGen(y1.D, y2.D, &B, (*CurvePoint)(&y1.PublicKey), (*CurvePoint)(&y2.PublicKey), A1, A2, &A)
			if err != nil {
				log.Fatal(err)
			}

			// 计算验证结果
			flag, err := ProofVrf(c, r1, r2, &B, (*CurvePoint)(&y1.PublicKey), (*CurvePoint)(&y2.PublicKey), A1, A2, &A)
			if err != nil {
				log.Fatal(err)
			}
			if false == flag {
				fmt.Println(i, "th value of var: ", flag)
			}
		}

	}
}

func TestShareReplace(t *testing.T) {
	// 集成于TestWorkFlow()，不单独测试
}

func TestWorkFlow(t *testing.T) {
	fmt.Println()

	////////////////////////
	// 模拟ks server数量/////
	lens := 100
	// 额外显示信息与否///////
	printt := true
	// prittt := false
	////////////////////////

	// 生成lens个ks server的公私钥对
	pks := make([]sm2.PrivateKey, lens) // 私钥slice
	Pks := make([]sm2.PublicKey, lens)  // 公钥slice
	for i := 0; i < lens; i++ {
		priv, err := GenPrivKey()
		if err != nil {
			log.Fatal(err)
		}
		pks[i] = *priv
		Pks[i] = priv.PublicKey
	}

	// 聚合ks server的公钥collPk
	collPk := CollPubKey(Pks)

	// 用户生成待加密的点D
	// 项目中，选择该点的2个坐标之一为文本的对称密钥
	D := GenPoint()

	// 用户使用聚合公钥collPk加密点D
	ct, _ := PointEncrypt(collPk, D)

	// 生成请求者公私钥对q
	q, err := GenPrivKey()
	if err != nil {
		log.Fatal(err)
	}
	Q := q.PublicKey

	// 5个server为q计算份额shares
	shares := make(CipherVector, lens)
	// ris := make([]big.Int,lens)

	for i := 0; i < lens; i++ {
		// 计算份额
		share, ri, _ := ShareCal(&Q, &ct.K, &pks[i])
		shares[i] = *share

		// 计算证明
		c, r1, r2, err := ShareProofGenNoB(ri, &pks[i], share, &Q, &ct.K)

		// 计算证明验证结果
		flag, err := ShareProofVryNoB(c, r1, r2, share, &pks[i].PublicKey, &Q, &ct.K)
		if err != nil {
			log.Fatal(err)
		}
		if false == flag {
			fmt.Println()
			fmt.Println(i, "th value of var: ", flag)
			fmt.Println()
		} else {
			// fmt.Println("   c:", c)
			// fmt.Println("  r1:", r1)
			// fmt.Println("  r2:", r2)
			// fmt.Println("flag:", flag)
		}
	}

	// q置换得到的份额，得到目标密文tct
	tct, err := ShareReplace(&shares, ct)

	// q从密文tct解密，得到明文点pt
	pt, err := PointDecrypt(tct, q)

	// 检查点D的坐标值是否与点pt的坐标值相同
	if 0 == D.X.Cmp(pt.X) && 0 == D.Y.Cmp(pt.Y) {
		fmt.Println("Eqal")
	} else {
		fmt.Println("not Eqal")
	}

	///////////////////////////
	// 额外显示信息/////////////
	if printt {
		fmt.Println()

		// for i := 0; i < lens; i++ { // ks server的公私钥
		// 	fmt.Println("pks[", i, "].D: ", pks[i].D)
		// 	fmt.Println("Pks[", i, "].X: ", Pks[i].X)
		// 	fmt.Println("Pks[", i, "].Y: ", Pks[i].Y)
		// }
		// fmt.Println("collPk.X: ", collPk.X) // 聚合公钥collPk
		// fmt.Println("collPk.Y: ", collPk.Y)
		// fmt.Println("q.D: ", q.D) // 请求者公私钥对
		// fmt.Println("Q.X: ", Q.X)
		// fmt.Println("Q.Y: ", Q.Y)
		// fmt.Println()
		fmt.Println("D.X: ", D.X) // 待加密点D
		fmt.Println("D.Y: ", D.Y)
		fmt.Println("pt.X:", pt.X) // 解密明文点pt
		fmt.Println("pt.Y:", pt.Y)

		fmt.Println()
	}
	///////////////////////////

	fmt.Println()
}
