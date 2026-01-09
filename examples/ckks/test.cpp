#include <iostream>
#include <cstring>
#include <memory>
#include <complex>

#include <torch/library.h>
#include <torch/script.h>
#include "framework/core/device.h"
#include "framework/core/caching_allocator.h"

int main()
{
    CAMBRICON_API::get_instance()->test();


    return 0;
}