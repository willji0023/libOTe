#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_MR_KYBER

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "coproto/Proto.h"

extern "C"
{
#include <KyberOT/KyberOT.h>
}

namespace osuCrypto
{


    class MasnyRindalKyber : public OtReceiver, public OtSender
    {
    public:


        coproto::Proto receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng) override;


        coproto::Proto send(
            span<std::array<block, 2>> messages,
            PRNG& prng)override;

#ifdef  ENABLE_BOOST

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            receive(choices, messages, prng, chl);
        }

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            send(messages, prng, chl);
        }

#endif //  ENABLE_BOOST


    };


}
#endif