#pragma once
#include <memory>
#include <functional>
#include <type_traits>

#ifndef NTSTATUS
typedef long NTSTATUS;
#endif

class FunctionStub
{
	private:
	void* pFunc = nullptr;

	public:
	FunctionStub() = default;
	FunctionStub(const FunctionStub&) = delete;
	FunctionStub(FunctionStub&&) = delete;
	FunctionStub& operator=(const FunctionStub&) = delete;
	FunctionStub& operator=(FunctionStub&&) = delete;
	~FunctionStub() = default;

	FunctionStub(void* pFunc) : pFunc(pFunc)
	{
	}

	template<typename... Args>
	NTSTATUS operator()(Args... args) const noexcept
	{
		using NTAPI_FUNCTION = NTSTATUS(*)(Args...);
		NTSTATUS(*pFunction)(Args...) = reinterpret_cast<NTAPI_FUNCTION>(pFunc);
		return pFunction(args...);
	}
};

