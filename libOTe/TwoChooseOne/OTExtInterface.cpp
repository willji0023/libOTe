#include "OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/BitVector.h>
#include <vector>
#include <cryptoTools/Network/Channel.h>
#include "coproto/NativeProto.h"
#include "coproto/Macros.h"
#include "libOTe/Tools/CoprotoSock.h"

#ifdef ENABLE_BOOST

void osuCrypto::OtExtReceiver::setBaseOts(span<std::array<block, 2>> baseSendOts, PRNG& prng, Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = setBaseOts(baseSendOts, prng).evaluate(s);
    if (ec)
        throw std::runtime_error("setBaseOts(), " + ec.message());
}

void osuCrypto::OtExtReceiver::genBaseOts(PRNG& prng, Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = genBaseOts(prng).evaluate(s);
    if (ec)
        throw std::runtime_error("genBaseOts(), " + ec.message());
}

void osuCrypto::OtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices, Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = setBaseOts(baseRecvOts, choices).evaluate(s);
    if (ec)
        throw std::runtime_error("setBaseOts(), " + ec.message());
}


void osuCrypto::OtExtSender::genBaseOts(PRNG& prng, Channel& chl)
{

    CoprotoSock s(chl);
    auto ec = genBaseOts(prng).evaluate(s);
    if (ec)
        throw std::runtime_error("setBaseOts(), " + ec.message());
}


void osuCrypto::OtReceiver::receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = receive(choices, messages, prng).evaluate(s);
    if (ec)
        throw std::runtime_error("OtReceiver::receive(), " + ec.message());
}

void osuCrypto::OtSender::send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = send(messages, prng).evaluate(s);
    if (ec)
        throw std::runtime_error("OtSender::send(), " + ec.message());
}

void osuCrypto::OtSender::sendChosen(
    span<std::array<block, 2>> messages,
    PRNG& prng,
    Channel& chl)
{

    CoprotoSock s(chl);
    auto ec = sendChosen(messages, prng).evaluate(s);
    if (ec)
        throw std::runtime_error("OtSender::sendChosen(), " + ec.message());
}

void osuCrypto::OtReceiver::receiveChosen(
    const BitVector& choices,
    span<block> recvMessages,
    PRNG& prng,
    Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = receiveChosen(choices, recvMessages, prng).evaluate(s);
    if (ec)
        throw std::runtime_error("OtSender::receiveChosen(), " + ec.message());
}

void osuCrypto::OtReceiver::receiveCorrelated(const BitVector& choices, span<block> recvMessages, PRNG& prng, Channel& chl)
{
    CoprotoSock s(chl);
    auto ec = receiveCorrelated(choices, recvMessages, prng).evaluate(s);
    if (ec)
        throw std::runtime_error("OtSender::receiveCorrelated(), " + ec.message());
}

#endif

coproto::Proto osuCrypto::OtExtReceiver::setBaseOts(span<std::array<block, 2>> baseSendOts, PRNG& prng)
{
    struct Proto : public coproto::NativeProto
    {
        OtExtReceiver& ot;
        span<std::array<block, 2>> baseSendOts;
        Proto(OtExtReceiver& o, span<std::array<block, 2>> b)
            :ot(o), baseSendOts(b) {}

        coproto::error_code resume() override
        {
            ot.setUniformBaseOts(baseSendOts);
            return {};
        }
    };

    return coproto::makeProto<Proto>(*this, baseSendOts);
}


coproto::Proto osuCrypto::OtExtReceiver::genBaseOts(PRNG& prng)
{
#ifdef LIBOTE_HAS_BASE_OT
    struct Base : coproto::NativeProto
    {
        OtExtReceiver& ot;
        PRNG& prng;
        DefaultBaseOT base;
        std::vector<std::array<block, 2>> msgs;

        Base(OtExtReceiver& o, PRNG& p)
            :ot(o)
            , prng(p)
        {}

        coproto::error_code resume() override
        {
            CP_BEGIN();
            msgs.resize(ot.baseOtCount());
            CP_AWAIT(base.send(msgs, prng));
            CP_AWAIT(ot.setBaseOts(msgs, prng));
            CP_END();
            return {};
        }
    };


    return coproto::makeProto<Base>(*this, prng);

#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif
}


coproto::Proto osuCrypto::OtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices)
{
    struct Proto : public coproto::NativeProto
    {
        OtExtSender& ot;
        span<block> baseRecvOts;
        const BitVector& choices;
        Proto(OtExtSender& o, span<block> b, const BitVector& c)
            :ot(o), baseRecvOts(b), choices(c) {}

        coproto::error_code resume() override
        {
            ot.setUniformBaseOts(baseRecvOts, choices);
            return {};
        }
    };

    return coproto::makeProto<Proto>(*this, baseRecvOts, choices);

}


coproto::Proto osuCrypto::OtExtSender::genBaseOts(PRNG& prng)
{
    struct Base : coproto::NativeProto
    {
        OtExtSender& ot;
        PRNG& prng;
        DefaultBaseOT base;
        std::vector<block> msgs;
        BitVector bv;

        Base(OtExtSender& o, PRNG& p)
            :ot(o)
            , prng(p)
        {}

        coproto::error_code resume() override
        {
            CP_BEGIN();
            msgs.resize(ot.baseOtCount());
            bv.resize(msgs.size());
            bv.randomize(prng);

            CP_AWAIT(base.receive(bv, msgs, prng));
            CP_AWAIT(ot.setBaseOts(msgs, bv));
            CP_END();
            return {};
        }
    };


    return coproto::makeProto<Base>(*this, prng);
}


coproto::Proto osuCrypto::OtReceiver::receiveChosen(const BitVector& choices, span<block> recvMessages, PRNG& prng)
{
    struct  Proto : coproto::NativeProto
    {
        OtReceiver& ot;
        const BitVector& choices;
        span<block> recvMessages;
        PRNG& prng;
        Proto(OtReceiver& o, const BitVector& c, span<block> m, PRNG& p)
            : ot(o)
            , choices(c)
            , recvMessages(m)
            , prng(p)
        {}

        std::vector<std::array<block, 2>> temp;
        coproto::error_code resume() override
        {
            CP_BEGIN();

            CP_AWAIT(ot.receive(choices, recvMessages, prng));
            temp.resize(recvMessages.size());
            CP_RECV(temp);
            {
                auto iter = choices.begin();
                for (u64 i = 0; i < temp.size(); ++i)
                {
                    recvMessages[i] = recvMessages[i] ^ temp[i][*iter];
                    ++iter;
                }
            }
            CP_END();
            return {};
        }
    };
    return coproto::makeProto<Proto>(*this, choices, recvMessages, prng);
}

coproto::Proto osuCrypto::OtReceiver::receiveCorrelated(const BitVector& choices, span<block> recvMessages, PRNG& prng)
{
    struct  Proto : coproto::NativeProto
    {
        OtReceiver& ot;
        const BitVector& choices;
        span<block> recvMessages;
        PRNG& prng;
        Proto(OtReceiver& o, const BitVector& c, span<block> m, PRNG& p)
            : ot(o)
            , choices(c)
            , recvMessages(m)
            , prng(p)
        {}

        std::vector<block> temp;
        coproto::error_code resume() override
        {
            CP_BEGIN();

            CP_AWAIT(ot.receive(choices, recvMessages, prng));
            temp.resize(recvMessages.size());
            CP_RECV(temp);
            //chl.recv(temp.data(), temp.size());
            {
                auto iter = choices.begin();
                for (u64 i = 0; i < temp.size(); ++i)
                {
                    recvMessages[i] = recvMessages[i] ^ (zeroAndAllOne[*iter] & temp[i]);
                    ++iter;
                }
            }
            CP_END();
            return {};
        }
    };
    return coproto::makeProto<Proto>(*this, choices, recvMessages, prng);
}

coproto::Proto osuCrypto::OtSender::sendChosen(span<std::array<block, 2>> messages, PRNG& prng)
{
    struct  Proto : coproto::NativeProto
    {
        OtSender& ot;
        span<std::array<block, 2>> messages;
        PRNG& prng;
        Proto(OtSender& o, span<std::array<block, 2>> m, PRNG& p)
            : ot(o)
            , messages(m)
            , prng(p)
        {}

        std::vector<std::array<block, 2>> temp;
        coproto::error_code resume() override
        {
            CP_BEGIN();

            temp.resize(messages.size());
            CP_AWAIT(ot.send(temp, prng));

            for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
            {
                temp[i][0] = temp[i][0] ^ messages[i][0];
                temp[i][1] = temp[i][1] ^ messages[i][1];
            }

            CP_SEND(std::move(temp));

            CP_END();
            return {};
        }

    };
    return coproto::makeProto<Proto>(*this, messages, prng);
}

coproto::Proto osuCrypto::OtSender::sendCorrelated(span<block> messages, std::function<block(block, u64)> corFunc, PRNG& prng)
{

    struct  Proto : coproto::NativeProto
    {
        OtSender& ot;
        span<block> messages;
        std::function<block(block, u64)> corFunc;
        PRNG& prng;
        Proto(OtSender& o, span<block> m, std::function<block(block, u64)>&& f, PRNG& p)
            : ot(o)
            , messages(m)
            , corFunc(std::move(f))
            , prng(p)
        {}

        std::vector<std::array<block, 2>> temp;
        std::vector<block> temp2;
        coproto::error_code resume() override
        {
            CP_BEGIN();


            temp.resize(messages.size());
            temp2.resize(messages.size());
            CP_AWAIT(ot.send(temp, prng));

            for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
            {
                messages[i] = temp[i][0];
                temp2[i] = temp[i][1] ^ corFunc(temp[i][0], i);
            }

            CP_SEND(std::move(temp2));

            CP_END();
            return {};
        }

    };
    return coproto::makeProto<Proto>(*this, messages, std::move(corFunc), prng);
}


