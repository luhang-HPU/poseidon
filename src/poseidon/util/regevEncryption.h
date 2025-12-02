#pragma once


// #include "math/ternaryuniformgenerator.h"
// #include "math/discreteuniformgenerator.h"
// #include "math/discretegaussiangenerator.h"
#include <gmp.h>
// #include <randomgen.h>
// #include <randomtostd.h>
// #include <secretkey.h>
// #include <util/clipnormal.h>
// #include <util/uintarithsmallmod.h>

#include <array>
#include <cassert>
#include <memory>
#include <vector>

#include <random>
#include <iostream>


using namespace std;

struct regevParam
{
    int n;
    int q;
    double std_dev;
    int m;
    regevParam()
    {
        n = 450;
        q = 65537;
        std_dev = 1.3;
        m = 16000;
    }
    regevParam(int n, int q, double std_dev, int m)
        : n(n), q(q), std_dev(std_dev), m(m)
    {
    }
};

typedef std::vector<uint64_t> NativeVector;
typedef uint64_t NativeInteger;

typedef NativeVector regevSK;

struct regevCiphertext{
    NativeVector a;
    NativeInteger b;
};

typedef vector<regevCiphertext> regevPK;

regevSK regevGenerateSecretKey(const regevParam& param);
regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk);
// regevPK regevGeneratePublicKey_Mod3(const regevParam& param, const regevSK& sk);
regevPK regevGenerateSquareRootInput(const regevParam& param, const regevSK& sk);
void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen = false);
// void regevEncSK_Mod3(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const int enc_num);
void regevEncSK_Value(regevCiphertext& ct, const int msg, const regevSK& sk, const regevParam& param);
void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param);
void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param);
void regevDec_Mod3(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param);
void regevDec_Value(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param, const int errorRange);

/////////////////////////////////////////////////////////////////// Below are implementation

regevSK regevGenerateSecretKey(const regevParam& param){
    int n = param.n;
    int q = param.q;

    // 随机数生成器
    std::random_device rd;
    std::mt19937_64 engine(rd());

    // 生成 0,1,p-1 的均匀分布
    std::uniform_int_distribution<int> dist(0, 2); // 0 -> 0, 1 -> 1, 2 -> p-1

    regevSK sk(n);

    for (int i = 0; i < n; i++)
    {
        int r = dist(engine);
        if (r == 0)
            sk[i] = 0;
        else if (r == 1)
            sk[i] = 1;
        else
            sk[i] = q - 1; // 代表 -1 mod p
    }
    return sk;
}


// regevPK regevGeneratePublicKey_Mod3(const regevParam& param, const regevSK& sk, const int enc_num = 0){
//     regevPK pk(param.m);
//     for(int i = 0; i < param.m; i++){
//         regevEncSK_Mod3(pk[i], 0, sk, param, enc_num);
//     }
//     return pk;
// }

// 简单的离散高斯采样（近似）
int64_t sample_discrete_gaussian(double std_dev, std::mt19937_64 &gen)
{
    std::normal_distribution<double> gauss(0.0, std_dev);
    return static_cast<int64_t>(std::round(gauss(gen)));
}

void regevEncSK_Value(regevCiphertext& ct, const int msg, const regevSK& sk, const regevParam& param, const int errorRange = 128){
    int n = param.n;
    uint64_t q = param.q;

    // 用标准 C++ 随机数生成器生成 a
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, q - 1);

    ct.a.resize(n);
    for (int i = 0; i < n; ++i) {
        ct.a[i] = dist(gen);
    }

    // 计算 b = <a,s> mod q
    uint64_t b = 0;
    for (int i = 0; i < n; ++i) {
        b = (b + (ct.a[i] * sk[i]) % q) % q;
    }

    // 加入明文
    if (msg != 0) {
        b = (b + (errorRange * msg) % q) % q;
    }

    // 加入噪声
    int64_t e = sample_discrete_gaussian(param.std_dev, gen);
    // 确保 e 模 q 是正整数
    b = (b + ((e % static_cast<int64_t>(q) + q) % q)) % q;

    ct.b = b;
}

// map 2^9 to 2^16
regevPK regevGenerateSquareRootInput(const regevParam& param, const regevSK& sk, const int plaintextSpace = 512, const int errorRange = 128){
    regevPK pk(param.m);
    // 加密0 - 511
    for(int i = 0; i < param.m; i++){
        int val = i % plaintextSpace; // the value to encrypt
        regevEncSK_Value(pk[i], val, sk, param, errorRange);
    }
    return pk;
}


void regevDec(vector<int>& msg, const vector<regevCiphertext>& ct, const regevSK& sk, const regevParam& param){
    msg.resize(ct.size());

    int q = param.q;
    int n = param.n;
    NativeInteger inner(0);
    for (int j = 0; j < (int) ct.size(); j++) {
        int r = ct[j].b;
        for (int i = 0; i < n; ++i) {
            r = (r - ct[j].a[i] * sk[i]) % q;
        }
        // r 在 0 - 16384 或者 r 在 49153 - 65537 判定为 0 ，r 在 1/4q - 3/4q 判定为 1；
        msg[j] = (r >= 0 && r < 65537/4) || (r < 65537 && r > 65537-65537/4) ? 0 : 1;
    }
}

// map 2^16 to 2^9
void regevDec_Value(vector<int>& msg, const vector<regevCiphertext>& ct, const regevSK& sk, const regevParam& param, const int errorRange){
    msg.resize(ct.size());

    int q = param.q;
    int n = param.n;
    NativeInteger inner(0);
    for (int i = 0; i < (int) ct.size(); i++) {
        int temp = 0;
        for (int j = 0; j < n; j++) {
            long mul_tmp = (ct[i].a[j] * sk[j]) % q;
            mul_tmp = mul_tmp < 0 ? mul_tmp + q : mul_tmp;
            temp = (temp + (int) mul_tmp) % q;
        }
        
        int r = (int)ct[i].b - temp;
        // 确保结果在 [0, q-1] 范围内
        r = (r % q + q) % q; 
        // 将大空间 q 映射到小空间 t，使用四舍五入偏移
        r = (r + errorRange/2) % q; 
        msg[i] = r / errorRange;
    }
    cout << endl;
}
