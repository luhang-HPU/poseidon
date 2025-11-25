#include "/usr/local/houmo/include/tcim/tcim_runtime.h"
// 文件在目录/usr/local/houmo/include/tcim下

#include <iostream>
#include <map>
#include <vector>

using namespace tcim;
using namespace std;


class HOUMO_API
{
public:
    HOUMO_API();

    // res = op1 + op2
    static void houmo_add(const int16_t* op1, const int16_t* op2, int16_t* res, int size);

    // res = op1 - op2
    static void houmo_sub(const int16_t* op1, const int16_t* op2, int16_t* res, int size);

    // res = op1 * p2
    static void houmo_mul(const int16_t* op1, const int16_t* op2, int16_t* res, int size);


private:
    const int size_ = 1024;
    const std::string path_add = "./add.hmm";
    const std::string path_sub = "./sub.hmm";
    const std::string path_mul = "./mul.hmm";

    tcim::Module module_add_;
    tcim::Module module_sub_;
    tcim::Module module_mul_;
};
