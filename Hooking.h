#pragma once

#include "SKSE/SKSE.h"

#define ByteAt(addr) *reinterpret_cast<std::uint8_t*>(addr)

/// Declraing a pre_hook function allows Hook to receive a call before the main hook will be installed.
template <typename Hook>
concept pre_hook = requires {
	{
		Hook::pre_hook()
	};
};

/// Declraing a post_hook function allows Hook to receive a call immediately after the main hook will be installed.
template <typename Hook>
concept post_hook = requires {
	{
		Hook::post_hook()
	};
};

/// Fundamental concept for a hook.
/// A hook must have a static thunk function that will be written to a trampoline.
template <typename Hook>
concept hook = requires {
	{
		Hook::thunk
	};
} || requires {
	typename Hook::Proxy;
	{
		Hook::Proxy::thunk
	};
};

/// Optionally Hook can define a static member named func that will contain the original function to chain the call.
/// static inline REL::Relocation<decltype(thunk)> func;
template <typename Hook>
concept chain_hook = requires {
	{
		Hook::func
	};
};

/// A hook that proxies it's call to another hook.
/// The Hook should define a nested type alias 'Proxy' that points to the hook type to proxy to.
template <typename Hook>
concept proxy_hook = requires {
	typename Hook::Proxy;
	requires hook<typename Hook::Proxy>;
};

/// Basic Hook that writes a call (write_call<5>) instruction to a thunk.
/// This also supports writing to lea instructions, which store function addresses.
template <typename Hook>
concept call_hook = hook<Hook> && requires {
	{
		Hook::relocation
	} -> std::convertible_to<REL::ID>;
	{
		Hook::offset
	} -> std::convertible_to<std::size_t>;
};

/// A type that has a vtable to hook into.
/// vtable_hook can only be used with Targets that have a vtable.
template <typename Target>
concept has_vtable = requires {
	{
		Target::VTABLE
	};
};

/// Defines required fields for a valid vtable hook.
/// Note that providing a custom vtable index is optional, if ommited `0`th table will be used by default.
template <typename Hook>
concept vtable_hook = hook<Hook> && requires {
	{
		Hook::index
	} -> std::convertible_to<std::size_t>;
	requires(has_vtable<typename Hook::Target>);
};

/// Allows to provide a custom vtable index for a vtable hook.
/// Note that providing a custom vtable index is optional, if ommited `0`th table will be used by default.
template <typename Hook>
concept custom_vtable_index = requires {
	{
		Hook::vtable
	} -> std::convertible_to<std::size_t>;
};

namespace stl
{
	using namespace SKSE::stl;

	
	namespace details
	{
		// Optional properties of a hook.
		template <vtable_hook Hook>
		constexpr std::size_t get_vtable() {
			if constexpr (custom_vtable_index<Hook>) {
				return Hook::vtable;  // Use the vtable if it exists
			} else {
				return 0;  // Default to 0 if vtable doesn't exist
			}
		}

		template <typename Hook>
		constexpr void set_func(std::uintptr_t func) {
			if constexpr (chain_hook<Hook>) {
				Hook::func = func;
			}
		}

		inline std::size_t requested_bytes = 0;

		void request_bytes(size_t bytes) {
			requested_bytes += bytes;
		}
	}

	// Right now we only use write_call<5>, so not much to worry about. The info below is just for reference.
	//
	// write_branch writes a jump instruction at the target,
	// write_call writes a call instruction at the target,
	// <5> allocates 14 bytes to do a absolute jump<SkyrimSE.exe->Tramoline Memory->AmazingPlugin.dll>,
	// <6> just allocates a 8 bytes(64 - bit value) that holds the address that'll go to<SkyirmSE.exe->[Trampoline Memory] -> AmazingPlugin.dll>

	template <hook Hook>
	void write_call(std::uintptr_t a_src) {
		auto& trampoline = SKSE::GetTrampoline();
		details::requested_bytes += 14;
		
		if constexpr (proxy_hook<Hook>) {
			details::set_func<Hook>(trampoline.write_call<5>(a_src, Hook::Proxy::thunk));
		} else {
			details::set_func<Hook>(trampoline.write_call<5>(a_src, Hook::thunk));
		}
	}

	template <has_vtable F, vtable_hook Hook>
	void write_vfunc() {
		REL::Relocation<std::uintptr_t> vtbl{ F::VTABLE[details::get_vtable<Hook>()] };
		if constexpr (proxy_hook<Hook>) {
			details::set_func<Hook>(vtbl.write_vfunc(Hook::index, Hook::Proxy::thunk));
		} else {
			details::set_func<Hook>(vtbl.write_vfunc(Hook::index, Hook::thunk));
		}
	}

	template <vtable_hook Hook>
	void write_vfunc() {
		write_vfunc<typename Hook::Target, Hook>();
	}

	template <call_hook Hook>
	void write_call() {
		const REL::Relocation<std::uintptr_t> rel{ Hook::relocation, Hook::offset };
		std::uintptr_t                        sourceAddress = rel.address();

		auto byteAddress = sourceAddress;
		auto opcode = ByteAt(byteAddress);

		if (opcode == 0xE8) {  // CALL instruction
			write_call<Hook>(sourceAddress);
		} else {
			auto                   leaSize = 7;
			constexpr std::uint8_t rexw = 0x48;
			if ((opcode & rexw) != rexw) {  // REX.W Must be present for a valid 64-bit address replacement.
				stl::report_and_fail("Invalid hook location, lea instruction must use 64-bit register (first byte should be between 0x48 and 04F)"sv);
			}
			opcode = ByteAt(++byteAddress);

			if (opcode == 0x8D) {                  // LEA instruction
				auto op1 = ByteAt(++byteAddress);  // Get first operand byte.
				auto opAddress = byteAddress;
				// Store original displacement
				std::int32_t disp = 0;
				for (std::uint8_t i = 0; i < 4; ++i) {
					disp |= ByteAt(++byteAddress) << (i * 8);
				}

				assert(disp != 0);
				// write CALL on top of LEA
				// This will fill new displacement
				// 8D MM XX XX XX XX -> 8D E8 YY YY YY YY (where MM is the operand #1, XX is the old func, and YY is the new func)
				write_call<Hook>(opAddress);

				// Restore operand byte
				// Since we overwrote first operand of lea we need to write it back
				// 8D E8 YY YY YY YY -> 8D MM YY YY YY YY
				REL::safe_write(opAddress, op1);

				// Find original function and store it in the hook's func.
				details::set_func<Hook>(sourceAddress + leaSize + disp);
			} else {
				stl::report_and_fail("Invalid hook location, write_thunk can only be used for call or lea instructions"sv);
			}
		}
	}

	/// <summary>
	/// Allocates trampoline memory and performs install function.
	/// After installation checks if enough trampoline memory was allocated and reports if not.
	/// 
	/// Alternative, one can use trace log level for SKSE, to read number of values in the log.
	/// 
	/// Generally, only call_hook require trampoline memory. 14 bytes per one call_hook.
	/// Allocating 14*N bytes should be enough for N hooks.
	/// </summary>
	/// <typeparam name="Installation">An empty function</typeparam>
	/// <param name="bytes">Memory size in bytes to allocate for trampoline</param>
	/// <param name="install">A lambda that should perform all install_hook calls.</param>
	template<typename Installation>
	void on_trampoline(size_t bytes, const Installation& install) {
		SKSE::AllocTrampoline(bytes);
		install();
		if (bytes < details::requested_bytes) {
			stl::report_and_fail(std::format("Not enough trampoline memory allocated. Requested: {}, Allocated: {}. Consider increasing the allocated trampoline size.", details::requested_bytes, bytes));
		}
		details::requested_bytes = 0;
	}

	/// Installs given hook.
	template <hook Hook>
	void install_hook() {
		if constexpr (chain_hook<Hook>) {
			using FuncType = decltype(Hook::func);
			if constexpr (proxy_hook<Hook>) {
				using ThunkType = decltype(Hook::Proxy::thunk);
				static_assert(std::is_same_v<REL::Relocation<ThunkType>, FuncType>, "Mismatching type of proxy thunk and func. 'Use static inline REL::Relocation<decltype(Proxy::thunk)> func;' to always match the type.");
			} else {
				using ThunkType = decltype(Hook::thunk);
				static_assert(std::is_same_v<REL::Relocation<ThunkType>, FuncType>, "Mismatching type of thunk and func. 'Use static inline REL::Relocation<decltype(thunk)> func;' to always match the type.");
			}
		}

		if constexpr (pre_hook<Hook>) {
			Hook::pre_hook();
		}

		if constexpr (call_hook<Hook>) {
			stl::write_call<Hook>();
		} else if constexpr (vtable_hook<Hook>) {
			stl::write_vfunc<Hook>();
		} else {
			static_assert(false, "Unsupported hook type. Hook must target either call, lea or vtable");
		}

		if constexpr (post_hook<Hook>) {
			Hook::post_hook();
		}
	}
}

#undef ByteAt
