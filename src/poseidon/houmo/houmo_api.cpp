#include "houmo_api.h"

#include <cstring>

HOUMO_API::HOUMO_API()
{
    module_add_ = tcim::Module::LoadFromFile(path_add);
    module_sub_ = tcim::Module::LoadFromFile(path_sub);
    module_mul_ = tcim::Module::LoadFromFile(path_mul);
}

void HOUMO_API::houmo_add(const int16_t *op1, const int16_t *op2, int16_t *res, int size)
{
    if (size <= 2048)
    {
        houmo_add_less_2048(op1, op2, res, size);
    }
    else
    {
        for(int i = 0; i < size; i += 2048)
        {
            int current_size = std::min(2048, size - i);
            houmo_add_less_2048(op1 + i, op2 + i, res + i, current_size);
        }
    }
}

void HOUMO_API::houmo_sub(const int16_t *op1, const int16_t *op2, int16_t *res, int size)
{
    if (size <= 2048)
    {
        houmo_sub_less_2048(op1, op2, res, size);
    }
    else
    {
        for (int i = 0; i < size; i += 2048)
        {
            int current_size = std::min(2048, size - i);
            houmo_sub_less_2048(op1 + i, op2 + i, res + i, current_size);
        }
    }
}

void HOUMO_API::houmo_mul(const int16_t *op1, const int16_t *op2, int16_t *res, int size)
{
    if (size <= 2048)
    {
        houmo_mul_less_2048(op1, op2, res, size);
    }
    else
    {
        for (int i = 0; i < size; i += 2048)
        {
            int current_size = std::min(2048, size - i);
            houmo_mul_less_2048(op1 + i, op2 + i, res + i, current_size);
        }
    }
}

void HOUMO_API::houmo_add_less_2048(const int16_t *op1, const int16_t *op2, int16_t *res, int size)
{
    int16_t x[size_];
    int16_t y[size_];
    int16_t z[size_];

    memset(x, 0, size_);
    memset(y, 0, size_);
    memset(z, 0, size_);

    memcpy(x, op1, 2 * size);
    memcpy(y, op2, 2 * size);

    tcim::Status stat;
    std::map<std::string, tcim::Tensor> input_map;
    
    // Get the total number of inputs
    int input_num = module_add_.GetInputNum();

    // create buffer on host, and transfer data
    tcim::Buffer input_x_buf = tcim::Buffer::CreateHostBuffer(2 * size_, x);
    tcim::Buffer input_y_buf = tcim::Buffer::CreateHostBuffer(2 * size_, y);
    tcim::Buffer output_buf = tcim::Buffer::CreateHostBuffer(2 * size_);

    // For each input:
    for (int idx = 0; idx < input_num; idx++)
    {
        // Get the name of the input
        auto input_name = module_add_.GetInputName(idx);
        // Get input data information
        auto input_info = module_add_.GetInputInfo(input_name).AsContiguous();
        // Allocate memory on host CPU for storing input data
        auto input_tensor = tcim::Tensor::CreateHostTensor(input_info, 2 * size_);

        // copy buffer to tensor buffer
        if (idx == 0)
        {
            stat = input_x_buf.CopyTo(input_tensor.Buffer());
            // std::cout << "copy1 status: " << stat << std::endl;
        }
        else if (idx == 1)
        {
            stat = input_y_buf.CopyTo(input_tensor.Buffer());
            // std::cout << "copy2 status: " << stat << std::endl;
        }

        // Create a map between input name and input tensor
        input_map.insert(std::pair<std::string, tcim::Tensor>(input_name, input_tensor));
    }

    // Loop through each key-value pair in the input_map
    for (const auto& input : input_map)
    {
        // Set each input with the key-value pair from the input_map
        auto status = module_add_.SetInput(input.first, input.second);
        if(status != tcim::Status::OK)
        {
            std::cout << "Failed to set input: " << input.first << std::endl;
            std::cout << "add setinput status: " << status << std::endl;
        }
            
    }

    module_add_.Run();
    module_add_.Sync();

    // Create a map to store output data
    std::map<std::string, tcim::Tensor> output_map;

    // Get total number of outputs
    int output_num = module_add_.GetOutputNum();
    //For each output:
    for (int idx = 0; idx < output_num; idx++)
    {
        // Get the name of the output
        auto output_name = module_add_.GetOutputName(idx);
        // Get the information of the output
        auto output_info = module_add_.GetOutputInfo(output_name).AsContiguous();
        // Allocate memory on host CPU for storing output data
        auto output_tensor = tcim::Tensor::CreateHostTensor(output_info, 2 * size_);
        // Insert the output name and tensor into the output map
        output_map.insert(std::pair<std::string, tcim::Tensor>(output_name, output_tensor));
    }

    // Loop through each key-value pair in the output_map
    for (auto& output : output_map)
    {
        // Get each output with the key-value pair from the output_map
        module_add_.GetOutput(output.first, output.second);

        output.second.Buffer().CopyTo(output_buf, 2 * size_);
        output_buf.CopyToHost(z, 2 * size_);
    }

    memcpy(res, z, 2 * size);
}

void HOUMO_API::houmo_sub_less_2048(const int16_t *op1, const int16_t *op2, int16_t *res, int size)
{
    int16_t x[size_];
    int16_t y[size_];
    int16_t z[size_];

    memset(x, 0, size_);
    memset(y, 0, size_);
    memset(z, 0, size_);

    memcpy(x, op1, 2 * size);
    memcpy(y, op2, 2 * size);

    tcim::Status stat;
    std::map<std::string, tcim::Tensor> input_map;
    // Get the total number of inputs
    int input_num = module_sub_.GetInputNum();

    // create buffer on host, and transfer data
    tcim::Buffer input_x_buf = tcim::Buffer::CreateHostBuffer(2 * size_, &op1);
    tcim::Buffer input_y_buf = tcim::Buffer::CreateHostBuffer(2 * size_, &op2);
    tcim::Buffer output_buf = tcim::Buffer::CreateHostBuffer(2 * size_);

    // For each input:
    for (int idx = 0; idx < input_num; idx++)
    {
        // Get the name of the input
        auto input_name = module_sub_.GetInputName(idx);
        // Get input data information
        auto input_info = module_sub_.GetInputInfo(input_name).AsContiguous();
        // Allocate memory on host CPU for storing input data
        auto input_tensor = tcim::Tensor::CreateHostTensor(input_info, 2 * size_);

        // copy buffer to tensor buffer
        if (idx == 0)
        {
            stat = input_x_buf.CopyTo(input_tensor.Buffer());
            // std::cout << "copy1 status: " << stat << std::endl;
        }
        else if (idx == 1)
        {
            stat = input_y_buf.CopyTo(input_tensor.Buffer());
            // std::cout << "copy2 status: " << stat << std::endl;
        }

        // Create a map between input name and input tensor
        input_map.insert(std::pair<std::string, tcim::Tensor>(input_name, input_tensor));
    }

    // Loop through each key-value pair in the input_map
    for (const auto& input : input_map)
    {
        // Set each input with the key-value pair from the input_map
        auto status = module_sub_.SetInput(input.first, input.second);
        if (status != tcim::Status::OK)
        {
            std::cout << "Failed to set input: " << input.first << std::endl;
            std::cout << "sub setinput status: " << status << std::endl;
        }
    }

    module_sub_.Run();
    module_sub_.Sync();

    // Create a map to store output data
    std::map<std::string, tcim::Tensor> output_map;

    // Get total number of outputs
    int output_num = module_sub_.GetOutputNum();
    //For each output:
    for (int idx = 0; idx < output_num; idx++)
    {
        // Get the name of the output
        auto output_name = module_sub_.GetOutputName(idx);
        // Get the information of the output
        auto output_info = module_sub_.GetOutputInfo(output_name).AsContiguous();
        // Allocate memory on host CPU for storing output data
        auto output_tensor = tcim::Tensor::CreateHostTensor(output_info, 2 * size_);
        // Insert the output name and tensor into the output map
        output_map.insert(std::pair<std::string, tcim::Tensor>(output_name, output_tensor));
    }

    // Loop through each key-value pair in the output_map
    for (auto& output : output_map)
    {
        // Get each output with the key-value pair from the output_map
        module_sub_.GetOutput(output.first, output.second);

        output.second.Buffer().CopyTo(output_buf, 2 * size_);
        output_buf.CopyToHost(z, 2 * size_);
    }

    memcpy(res, z, 2 * size);
}

void HOUMO_API::houmo_mul_less_2048(const int16_t *op1, const int16_t *op2, int16_t *res, int size)
{
    int16_t x[size_];
    int16_t y[size_];
    int16_t z[size_];

    memset(x, 0, size_);
    memset(y, 0, size_);
    memset(z, 0, size_);

    memcpy(x, op1, 2 * size);
    memcpy(y, op2, 2 * size);

    tcim::Status stat;
    std::map<std::string, tcim::Tensor> input_map;
    // Get the total number of inputs
    int input_num = module_mul_.GetInputNum();

    // create buffer on host, and transfer data
    tcim::Buffer input_x_buf = tcim::Buffer::CreateHostBuffer(2 * size_, &op1);
    tcim::Buffer input_y_buf = tcim::Buffer::CreateHostBuffer(2 * size_, &op2);
    tcim::Buffer output_buf = tcim::Buffer::CreateHostBuffer(2 * size_);


    // For each input:
    for (int idx = 0; idx < input_num; idx++)
    {
        // Get the name of the input
        auto input_name = module_mul_.GetInputName(idx);
        // Get input data information
        auto input_info = module_mul_.GetInputInfo(input_name).AsContiguous();
        // Allocate memory on host CPU for storing input data
        auto input_tensor = tcim::Tensor::CreateHostTensor(input_info, 2 * size_);

        // copy buffer to tensor buffer
        if (idx == 0)
        {
            stat = input_x_buf.CopyTo(input_tensor.Buffer());
            // std::cout << "copy1 status: " << stat << std::endl;
        }
        else if (idx == 1)
        {
            stat = input_y_buf.CopyTo(input_tensor.Buffer());
            // std::cout << "copy2 status: " << stat << std::endl;
        }

        // Create a map between input name and input tensor
        input_map.insert(std::pair<std::string, tcim::Tensor>(input_name, input_tensor));
    }

    // Loop through each key-value pair in the input_map
    for (const auto& input : input_map)
    {
        // Set each input with the key-value pair from the input_map
        auto status = module_mul_.SetInput(input.first, input.second);
        if (status != tcim::Status::OK)
        {
            std::cout << "Failed to set input: " << input.first << std::endl;
            std::cout << "mul setinput status: " << status << std::endl;
        }
    }

    module_mul_.Run();
    module_mul_.Sync();

    // Create a map to store output data
    std::map<std::string, tcim::Tensor> output_map;

    // Get total number of outputs
    int output_num = module_mul_.GetOutputNum();
    //For each output:
    for (int idx = 0; idx < output_num; idx++)
    {
        // Get the name of the output
        auto output_name = module_mul_.GetOutputName(idx);
        // Get the information of the output
        auto output_info = module_mul_.GetOutputInfo(output_name).AsContiguous();
        // Allocate memory on host CPU for storing output data
        auto output_tensor = tcim::Tensor::CreateHostTensor(output_info, 2 * size_);
        // Insert the output name and tensor into the output map
        output_map.insert(std::pair<std::string, tcim::Tensor>(output_name, output_tensor));
    }

    // Loop through each key-value pair in the output_map
    for (auto& output : output_map)
    {
        // Get each output with the key-value pair from the output_map
        module_mul_.GetOutput(output.first, output.second);

        output.second.Buffer().CopyTo(output_buf, 2 * size_);
        output_buf.CopyToHost(z, 2 * size_);
    }

    memcpy(res, z, 2 * size);
}