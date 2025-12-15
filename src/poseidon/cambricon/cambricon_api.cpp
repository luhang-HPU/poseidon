#include "cambricon_api.h"


at::Device CAMBRICON_API::device_ = at::Device("mlu:0");

std::shared_ptr<CAMBRICON_API> CAMBRICON_API::cambricon_api_ = nullptr;