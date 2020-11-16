#pragma once
#include "coproto/Scheduler.h"
#include "cryptoTools/Network/Channel.h"

namespace osuCrypto
{
#ifdef ENABLE_BOOST

	struct CoprotoSock : public coproto::Socket
	{
		Channel mChl;
		CoprotoSock(Channel& chl)
			: mChl(chl)
		{}
		CoprotoSock() = default;
		CoprotoSock(const CoprotoSock&) = default;
		CoprotoSock(CoprotoSock&&) = default;
		CoprotoSock& operator=(const CoprotoSock&) = default;
		CoprotoSock& operator=(CoprotoSock&&) = default;

		coproto::error_code recv(coproto::span<u8> data) override
		{
			try {
				mChl.recv(data);
			}
			catch (BadReceiveBufferSize& b)
			{
				return coproto::code::badBufferSize;
			}

			return {};
		}
		coproto::error_code send(coproto::span<u8> data)override
		{
			mChl.send(data);
			return {};
		};
		void cancel()override
		{
			mChl.cancel();
		}
	};


	inline coproto::error_code evaluate(coproto::Proto&& proto, Channel& chl)
	{
		CoprotoSock sock(chl);
		return proto.evaluate(sock);
	}

#endif

}