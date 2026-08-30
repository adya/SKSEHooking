#pragma once

#include "REL/Pattern.h"
#include "SKSE/SKSE.h"

#include <algorithm>
#include <ranges>

#define ByteAt(addr) *reinterpret_cast<std::uint8_t*>(addr)

/// Fixed-size compile-time string used to declare a hook's byte signature, e.g.:
/// static inline constexpr Signature signature{ "48 8B 05 ?? ?? ?? ?? 48 63 C9" };
template <typename CharT, std::size_t N>
using Signature = SKSE::stl::nttp::string<CharT, N>;

/// A set of fixed-size compile-time strings used to declare a hook's byte signature for multiple runtimes, e.g.:
/// static inline constexpr VariantSignature<"48 8B 05 ?? ?? ?? ??", "4C 8B 05 ?? ?? ?? ??"> signature;
template <Signature SE, Signature AE = Signature<char, 0>{ "" }, Signature VR = Signature<char, 0>{ "" }>
struct VariantSignature
{
	static void match_or_fail(std::uintptr_t address)
	{
		switch (REL::Module::GetRuntime()) {
		case REL::Module::Runtime::SE:
			if constexpr (!SE.empty()) {
				REL::make_pattern<SE>().match_or_fail(address);
			}
			return;
		case REL::Module::Runtime::AE:
			if constexpr (!AE.empty()) {
				REL::make_pattern<AE>().match_or_fail(address);
			}
			return;
		case REL::Module::Runtime::VR:
			if constexpr (!VR.empty()) {
				REL::make_pattern<VR>().match_or_fail(address);
			}
			return;
		}
	}
};

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

/// A hook that can be verified with a signature - space-separated hex byte pattern at installation time.
/// This confirms that the hook is being installed at the intended address and that the target region of code has not changed.
template <typename Hook>
concept signature_hook = requires {
	{
		REL::make_pattern<Hook::signature>()
	};
} || requires(std::uintptr_t address) {
	{
		Hook::signature.match_or_fail(address)
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
	requires std::constructible_from<REL::Relocation<std::uintptr_t>, decltype(Hook::relocation), decltype(Hook::offset)>;
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

/// Declaring min_version restricts a hook to runtimes at or above the given REL::Version.
/// static inline constexpr REL::Version min_version{ SKSE::RUNTIME_SSE_1_6_640 };
template <typename Hook>
concept min_versioned_hook = requires {
	{
		Hook::min_version
	} -> std::convertible_to<REL::Version>;
};

/// Declaring max_version restricts a hook to runtimes at or below the given REL::Version.
/// static inline constexpr REL::Version max_version{ SKSE::RUNTIME_SSE_1_6_1130 };
template <typename Hook>
concept max_versioned_hook = requires {
	{
		Hook::max_version
	} -> std::convertible_to<REL::Version>;
};

/// Declaring exact_versions restricts a hook to only the listed runtimes.
/// Can be any range of REL::Version (e.g. std::array), so it composes with min_version/max_version if both are present.
/// static inline constexpr std::array exact_versions{ SKSE::RUNTIME_SSE_1_6_640, SKSE::RUNTIME_SSE_1_6_1170 };
template <typename Hook>
concept exact_versioned_hook = requires {
	{
		Hook::exact_versions
	} -> std::ranges::range;
	requires std::convertible_to<std::ranges::range_value_t<decltype(Hook::exact_versions)>, REL::Version>;
};

/// A hook that only installs on runtimes matching its declared version constraints.
/// Combine any subset of min_version, max_version and exact_versions; all declared constraints must be satisfied.
template <typename Hook>
concept versioned_hook = min_versioned_hook<Hook> || max_versioned_hook<Hook> || exact_versioned_hook<Hook>;

/// Declaring runtime restricts a hook to a single REL::Module::Runtime (SE, AE or VR).
/// static inline constexpr REL::Module::Runtime runtime{ REL::Module::Runtime::AE };
template <typename Hook>
concept runtime_hook = requires {
	{
		Hook::runtime
	} -> std::convertible_to<REL::Module::Runtime>;
};

/// A hook that only installs when its declared constraints are met by the running game.
/// Combine any subset of min_version, max_version, exact_versions and runtime; all declared constraints must be satisfied.
/// install_hook silently skips a hook whose constraints aren't met.
template <typename Hook>
concept conditional_hook = versioned_hook<Hook> || runtime_hook<Hook>;

namespace stl
{
	using namespace SKSE::stl;

	namespace details
	{
		// Optional properties of a hook.
		template <vtable_hook Hook>
		constexpr std::size_t get_vtable()
		{
			if constexpr (custom_vtable_index<Hook>) {
				return Hook::vtable;  // Use the vtable if it exists
			} else {
				return 0;  // Default to 0 if vtable doesn't exist
			}
		}

		template <typename Hook>
		constexpr void set_func(std::uintptr_t func)
		{
			if constexpr (chain_hook<Hook>) {
				Hook::func = func;
			}
		}

		template <signature_hook Hook>
		void verify_signature(std::uintptr_t address)
		{
			if constexpr (requires { Hook::signature.match_or_fail(address); }) {
				Hook::signature.match_or_fail(address);
			} else {
				REL::make_pattern<Hook::signature>().match_or_fail(address);
			}
		}

		template <conditional_hook Hook>
		bool is_hook_enabled()
		{
			if constexpr (runtime_hook<Hook>) {
				if (REL::Module::GetRuntime() != Hook::runtime) {
					return false;
				}
			}

			if constexpr (versioned_hook<Hook>) {
				const auto version = REL::Module::get().version();

				if constexpr (min_versioned_hook<Hook>) {
					if (version < Hook::min_version) {
						return false;
					}
				}
				if constexpr (max_versioned_hook<Hook>) {
					if (version > Hook::max_version) {
						return false;
					}
				}
				if constexpr (exact_versioned_hook<Hook>) {
					if (std::ranges::find(Hook::exact_versions, version) == std::ranges::end(Hook::exact_versions)) {
						return false;
					}
				}
			}

			return true;
		}
	}

	// Right now we only use write_call<5>, so not much to worry about. The info below is just for reference.
	//
	// write_branch writes a jump instruction at the target,
	// write_call writes a call instruction at the target,
	// <5> allocates 14 bytes to do a absolute jump<SkyrimSE.exe->Tramoline Memory->AmazingPlugin.dll>,
	// <6> just allocates a 8 bytes(64 - bit value) that holds the address that'll go to<SkyirmSE.exe->[Trampoline Memory] -> AmazingPlugin.dll>

	template <hook Hook>
	void write_call(std::uintptr_t a_src)
	{
		auto& trampoline = SKSE::GetTrampoline();

		if constexpr (proxy_hook<Hook>) {
			details::set_func<Hook>(trampoline.write_call<5>(a_src, Hook::Proxy::thunk));
		} else {
			details::set_func<Hook>(trampoline.write_call<5>(a_src, Hook::thunk));
		}
	}

	template <has_vtable F, vtable_hook Hook>
	void write_vfunc()
	{
		REL::Relocation<std::uintptr_t> vtbl{ F::VTABLE[details::get_vtable<Hook>()] };
		if constexpr (proxy_hook<Hook>) {
			details::set_func<Hook>(vtbl.write_vfunc(Hook::index, Hook::Proxy::thunk));
		} else {
			details::set_func<Hook>(vtbl.write_vfunc(Hook::index, Hook::thunk));
		}
	}

	template <vtable_hook Hook>
	void write_vfunc()
	{
		write_vfunc<typename Hook::Target, Hook>();
	}

	template <call_hook Hook>
	void write_call()
	{
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

	/// Installs given hook.
	template <hook Hook>
	void install_hook()
	{
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

		if constexpr (conditional_hook<Hook>) {
			if (!details::is_hook_enabled<Hook>()) {
				return;
			}
		}

		if constexpr (call_hook<Hook> && signature_hook<Hook>) {
			const REL::Relocation<std::uintptr_t> rel{ Hook::relocation, Hook::offset };
			details::verify_signature<Hook>(rel.address());
		}

		if constexpr (pre_hook<Hook>) {
			Hook::pre_hook();
		}

		if constexpr (call_hook<Hook>) {
			stl::write_call<Hook>();
		} else if constexpr (vtable_hook<Hook>) {
			static_assert(!signature_hook<Hook>, "signature verification is only supported for call_hook.");
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
