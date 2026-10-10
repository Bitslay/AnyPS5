#include "prx/libSceAgc/Cb/include/Registers.hpp"

#include "prx/libSceAgc/Command/include/Packet.hpp"
#include <cstdint>
#include <cstddef>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"

#include "SceShaders.hpp"
#include <map>
#include <unordered_set>
#include <cstdio>
#include <cstring>

extern "C" void AgcDriverRegisterShader_nid_postfix(const Shader* shader);

namespace {

std::map<std::uint32_t, std::uint32_t> trackedShRegisters;
std::unordered_set<std::uint64_t> registeredShaders;

alignas(256) std::uint8_t syntheticHeaderBuffer[4096];

std::uint32_t RegisterListSize(std::uint32_t numRegs, const char* function) {
    constexpr std::uint32_t bytesPerRegister = 3u * sizeof(std::uint32_t);
    Agc::Command::Require(numRegs <= 0xffffffffu / bytesPerRegister, function, "register list size overflow");
    return numRegs * bytesPerRegister;
}

}

namespace Agc::Cb {

void EnsureComputeShaderRegistered() {
    auto itC = trackedShRegisters.find(0x20c);
    auto itD = trackedShRegisters.find(0x20d);
    if (itC == trackedShRegisters.end() || itD == trackedShRegisters.end()) return;

    const std::uint64_t low = itC->second;
    const std::uint64_t high = itD->second;
    const std::uint64_t pgm_addr = (low << 8u) | ((high & 0xffu) << 40u);
    if (pgm_addr == 0 || registeredShaders.contains(pgm_addr)) return;

    registeredShaders.insert(pgm_addr);

    const auto* code = reinterpret_cast<const std::uint32_t*>(pgm_addr);
    std::uint32_t word_count = 64;
    for (std::uint32_t i = 0; i < 65536; ++i) {
        const std::uint32_t word = code[i];
        const std::uint32_t op = word >> 16u;
        if (op == 0xBF81u || op == 0xBF9Fu || op == 0xBF8Bu || op == 0xBF9Eu) {
            word_count = i + 1;
            break;
        }
    }

    std::memset(syntheticHeaderBuffer, 0, sizeof(syntheticHeaderBuffer));

    auto* shader = reinterpret_cast<Shader*>(syntheticHeaderBuffer);
    auto* specials = reinterpret_cast<ShaderSpecialRegs*>(syntheticHeaderBuffer + sizeof(Shader));
    auto* shRegs = reinterpret_cast<ShaderRegister*>(syntheticHeaderBuffer + sizeof(Shader) + sizeof(ShaderSpecialRegs));

    std::uint32_t regCount = 0;
    for (const auto& [offset, val] : trackedShRegisters) {
        if (sizeof(Shader) + sizeof(ShaderSpecialRegs) + (regCount + 1) * sizeof(ShaderRegister) > sizeof(syntheticHeaderBuffer)) break;
        shRegs[regCount].offset = offset;
        shRegs[regCount].value = val;
        ++regCount;
    }

    specials->dispatch_modifier = 0x41u;

    shader->file_header = 0x34333231u;
    shader->version = 0x18u;
    shader->code = reinterpret_cast<const void*>(pgm_addr);
    shader->shader_size = word_count * sizeof(std::uint32_t);
    shader->header_size = sizeof(Shader) + sizeof(ShaderSpecialRegs) + regCount * sizeof(ShaderRegister);
    shader->type = 0;
    shader->specials = specials;
    shader->sh_registers = shRegs;
    shader->num_sh_registers = static_cast<std::uint8_t>(regCount);

    AgcDriverRegisterShader_nid_postfix(shader);
    std::fprintf(stderr, "[libSceAgc] Registered raw compute shader at 0x%llx (size %u words, %u regs)\n",
        static_cast<unsigned long long>(pgm_addr), word_count, regCount);
}

}

extern "C" {

std::uint32_t* APS5_VABI sceAgcCbSetUcRegisterRangeDirect(CommandBuffer* buf, std::uint32_t offset, const std::uint32_t* values, std::uint32_t numValues) {
    return Agc::Command::WriteRegisterRange(buf, 0x79u, offset, values, numValues, __func__);
}

std::uint32_t* APS5_VABI sceAgcCbSetShRegisterRangeDirect(CommandBuffer* buf, std::uint32_t offset, const std::uint32_t* values, std::uint32_t numValues) {
    if (values != nullptr) {
        for (std::uint32_t i = 0; i < numValues; ++i) {
            trackedShRegisters[offset + i] = values[i];
        }
    }
    return Agc::Command::WriteRegisterRange(buf, 0x76u, offset, values, numValues, __func__);
}

uint32_t APS5_VABI sceAgcCbSetShRegisterRangeDirectGetSize(uint32_t num_values) {
    return (num_values + 2u) * 4u;
}

std::uint32_t APS5_VABI sceAgcCbSetUcRegisterRangeDirectGetSize(std::uint32_t numValues) {
    return (numValues + 2u) * 4u;
}

std::uint32_t* APS5_VABI sceAgcCbSetShRegistersDirect(CommandBuffer* buf, const volatile ShaderRegister* regs, std::uint32_t numRegs) {
    return Agc::Command::WriteRegisters(buf, 0x76u, regs, numRegs, true, __func__);
}

std::uint32_t APS5_VABI sceAgcCbSetShRegistersDirectGetSize(std::uint32_t numRegs) {
    return RegisterListSize(numRegs, __func__);
}

std::uint32_t* APS5_VABI sceAgcCbSetUcRegistersDirect(CommandBuffer* buf, const volatile ShaderRegister* regs, std::uint32_t numRegs) {
    return Agc::Command::WriteRegisters(buf, 0x79u, regs, numRegs, false, __func__);
}

std::uint32_t APS5_VABI sceAgcCbSetUcRegistersDirectGetSize(std::uint32_t numRegs) {
    return RegisterListSize(numRegs, __func__);
}

}
