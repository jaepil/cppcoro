///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_ACCEPT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_ACCEPT_OPERATION_HPP_INCLUDED

#include <cppcoro/config.hpp>
#include <cppcoro/cancellation_token.hpp>
#include <cppcoro/cancellation_registration.hpp>

#include <atomic>
#include <optional>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>
#elif CPPCORO_OS_LINUX
# include <cppcoro/detail/linux.hpp>
# include <cppcoro/detail/linux_async_operation.hpp>
#endif


namespace cppcoro
{
	namespace net
	{
#if CPPCORO_OS_WINNT
		class socket;

		class socket_accept_operation_impl
		{
		public:

			socket_accept_operation_impl(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_listeningSocket(listeningSocket)
				, m_acceptingSocket(acceptingSocket)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

#if CPPCORO_COMPILER_MSVC
# pragma warning(push)
# pragma warning(disable : 4324) // Structure padded due to alignment
#endif

			socket& m_listeningSocket;
			socket& m_acceptingSocket;
			alignas(8) std::uint8_t m_addressBuffer[88];

#if CPPCORO_COMPILER_MSVC
# pragma warning(pop)
#endif

		};

		class socket_accept_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_accept_operation>
		{
		public:

			socket_accept_operation(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_accept_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};

		class socket_accept_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>
		{
		public:

			socket_accept_operation_cancellable(
				socket& listeningSocket,
				socket& acceptingSocket,
				cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>(std::move(ct))
				, m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};
#elif CPPCORO_OS_LINUX
		class socket;

		class socket_accept_operation_impl
		{
		public:

			socket_accept_operation_impl(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_listeningSocket(listeningSocket)
				, m_acceptingSocket(acceptingSocket)
			{}

			bool try_start(cppcoro::detail::linux_async_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::linux_async_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::linux_async_operation_base& operation);

		private:
			socket& m_listeningSocket;
			socket& m_acceptingSocket;
			alignas(8) std::uint8_t m_addressBuffer[88];
		};

		class socket_accept_operation
			: public cppcoro::detail::linux_async_operation<socket_accept_operation>
		{
		public:

			socket_accept_operation(
				socket& listeningSocket,
				socket& acceptingSocket,
				cppcoro::detail::linux::message_queue* mq) noexcept
				: cppcoro::detail::linux_async_operation<socket_accept_operation>(mq)
				, m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::linux_async_operation<socket_accept_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};

		class socket_accept_operation_cancellable
			: public cppcoro::detail::linux_async_operation_cancellable<socket_accept_operation_cancellable>
		{
		public:

			socket_accept_operation_cancellable(
				socket& listeningSocket,
				socket& acceptingSocket,
				cppcoro::detail::linux::message_queue* mq,
				cancellation_token&& ct) noexcept
				: cppcoro::detail::linux_async_operation_cancellable<socket_accept_operation_cancellable>(mq, std::move(ct))
				, m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::linux_async_operation_cancellable<socket_accept_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};
#endif
	}
}


#endif
