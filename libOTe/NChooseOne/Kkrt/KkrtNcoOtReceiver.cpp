#include "libOTe/Base/BaseOT.h"
#ifdef ENABLE_KKRT
#include "KkrtNcoOtReceiver.h"
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include  <mmintrin.h>
#include "KkrtDefines.h"
#include <cryptoTools/Crypto/RandomOracle.h>

#include <coproto/NativeProto.h>
#include <coproto/Macros.h>

namespace osuCrypto
{
    void KkrtNcoOtReceiver::setUniformBaseOts(
        gsl::span<std::array<block, 2>> baseRecvOts)
    {

        if (baseRecvOts.size() % 128 != 0)
            throw std::runtime_error("rt error at " LOCATION);

        if (u64(baseRecvOts.size())!= u64(mGens.size()))
            throw std::runtime_error("rt error at " LOCATION);


        //mGens.resize(baseRecvOts.size());
        mGensBlkIdx.resize(baseRecvOts.size(), 0);

        for (u64 i = 0; i < mGens.size(); i++)
        {
            mGens[i][0].setKey(baseRecvOts[i][0]);
            mGens[i][1].setKey(baseRecvOts[i][1]);
        }
    }


    coproto::Proto KkrtNcoOtReceiver::init(u64 numOtExt, PRNG& prng)
    {
        static const u64 superBlkSize(8);
        struct Proto : coproto::NativeProto
        {
            KkrtNcoOtReceiver& ot;
            u64 numOtExt;
            PRNG& prng;
            Proto(KkrtNcoOtReceiver& o, u64 n, PRNG& p)
                :ot(o)
                , numOtExt(n)
                , prng(p) {}

            coproto::error_code resume() override
            {

                CP_BEGIN();

                if (ot.hasBaseOts() == false)
                    CP_AWAIT(ot.genBaseOts(prng));

                {
                    // this will be used as temporary buffers of 128 columns,
                    // each containing 1024 bits. Once transposed, they will be copied
                    // into the T1, T0 buffers for long term storage.
                    std::array<std::array<block, superBlkSize>, 128> t0;
                    std::array<std::array<block, superBlkSize>, 128> t1;

                    // we are going to process OTs in blocks of 128 * superblkSize messages.
                    u64 numSuperBlocks = ((numOtExt + 127) / 128 + superBlkSize - 1) / superBlkSize;
                    u64 numCols = ot.mGens.size();

                    // We need two matrices, T0 and T1. These will hold the expanded and transposed
                    // rows that we got the using the base OTs as PRNG seed.
                    ot.mT0.resize(numOtExt, numCols / 128);
                    ot.mT1.resize(numOtExt, numCols / 128);

                    // The is the index of the last correction value u = T0 ^ T1 ^ c(w)
                    // that was sent to the sender.
                    ot.mCorrectionIdx = 0;

                    // the index of the OT that has been completed.
                    u64 doneIdx = 0;

                    // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
                    //   Instead we break it down into smaller chunks. We do 128 columns
                    //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
                    //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
                    //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
                    //   So that's what we do.
                    for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
                    {
                        // compute at what row does the user want us to stop.
                        // The code will still compute the transpose for these
                        // extra rows, but it is thrown away.
                        u64 stopIdx
                            = doneIdx
                            + std::min<u64>(u64(128) * superBlkSize, numOtExt - doneIdx);


                        for (u64 i = 0; i < numCols / 128; ++i)
                        {

                            for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                            {
                                // generate the column indexed by colIdx. This is done with
                                // AES in counter mode acting as a PRNG. We don't use the normal
                                // PRNG interface because that would result in a data copy when
                                // we move it into the T0,T1 matrices. Instead we do it directly.
                                ot.mGens[colIdx][0].ecbEncCounterMode(ot.mGensBlkIdx[colIdx], superBlkSize, ((block*)t0.data() + superBlkSize * tIdx));
                                ot.mGens[colIdx][1].ecbEncCounterMode(ot.mGensBlkIdx[colIdx], superBlkSize, ((block*)t1.data() + superBlkSize * tIdx));

                                // increment the counter mode idx.
                                ot.mGensBlkIdx[colIdx] += superBlkSize;
                            }

                            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                            // each 128 bits wide.
                            transpose128x1024(t0);
                            transpose128x1024(t1);

                            // This is the index of where we will store the matrix long term.
                            // doneIdx is the starting row. i is the offset into the blocks of 128 bits.
                            // __restrict isn't crucial, it just tells the compiler that this pointer
                            // is unique and it shouldn't worry about pointer aliasing.
                            block* __restrict mT0Iter = ot.mT0.data() + ot.mT0.stride() * doneIdx + i;
                            block* __restrict mT1Iter = ot.mT1.data() + ot.mT1.stride() * doneIdx + i;

                            for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                            {
                                // because we transposed 1024 rows, the indexing gets a bit weird. But this
                                // is the location of the next row that we want. Keep in mind that we had long
                                // **contiguous** columns.
                                block* __restrict t0Iter = ((block*)t0.data()) + j;
                                block* __restrict t1Iter = ((block*)t1.data()) + j;

                                // do the copy!
                                for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                                {
                                    *mT0Iter = *(t0Iter);
                                    *mT1Iter = *(t1Iter);

                                    t0Iter += superBlkSize;
                                    t1Iter += superBlkSize;

                                    mT0Iter += ot.mT0.stride();
                                    mT1Iter += ot.mT0.stride();
                                }
                            }
                        }

                        doneIdx = stopIdx;
                    }


                    std::array<block, 4> keys;
                    PRNG(ZeroBlock).get(keys.data(), keys.size());
                    ot.mMultiKeyAES.setKeys(keys);

                }
                CP_END();
                return {};
            }
        };


        return coproto::makeProto<Proto>(*this, numOtExt, prng);
    }


    u64 KkrtNcoOtReceiver::getBaseOTCount() const
    {
        if (mGens.size())
            return mGens.size();
        else
            throw std::runtime_error("must call configure(...) before getBaseOTCount() " LOCATION);
    }

    KkrtNcoOtReceiver KkrtNcoOtReceiver::splitBase()
    {
        KkrtNcoOtReceiver raw;
        raw.mGens.resize(mGens.size());
        raw.mInputByteCount = mInputByteCount;
        raw.mMultiKeyAES = mMultiKeyAES;

        if (hasBaseOts())
        {
            std::vector<std::array<block, 2>> base(mGens.size());

            for (u64 i = 0; i < base.size(); ++i)
            {
                mGens[i][0].ecbEncCounterMode(mGensBlkIdx[i], 1, &base[i][0]);
                mGens[i][1].ecbEncCounterMode(mGensBlkIdx[i], 1, &base[i][1]);

                ++mGensBlkIdx[i];
            }
            raw.setUniformBaseOts(base);
        }
        return (raw);
    }

    std::unique_ptr<NcoOtExtReceiver> KkrtNcoOtReceiver::split()
    {
        return std::make_unique<KkrtNcoOtReceiver>(std::move(splitBase()));
    }


    void KkrtNcoOtReceiver::encode(
        u64 otIdx,
        const void* input,
        void* dest,
        u64 destSize)
    {
        static const int width(4);
#ifndef NDEBUG
        if (mT0.stride() != width)
            throw std::runtime_error(LOCATION);

        //if (choice.size() != mT0.stride())
        //    throw std::invalid_argument("");

        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extension");

        if (eq(mT0[otIdx][0], AllOneBlock))
            throw std::runtime_error("This otIdx has already been encoded");
#endif // !NDEBUG

        block* t0Val = mT0.data() + mT0.stride() * otIdx;
        block* t1Val = mT1.data() + mT0.stride() * otIdx;

        // 128 bit input restriction
        block word = ZeroBlock;
        memcpy(&word, input, mInputByteCount);

        // run the input word through AES to get a psuedo-random codeword. Then
        // XOR the input with the AES output.
        std::array<block, width> choice{ word,word ,word ,word }, code;
        mMultiKeyAES.ecbEncNBlocks(choice.data(), code.data());

        // encode the correction value as u = T0 + T1 + c(w), there c(w) is a pseudo-random codeword.
        
            for (u64 i = 0; i < width; ++i)
            {
                // final code is the output of AES plus the input
                code[i] = code[i] ^ choice[i];

                // reuse mT1 as the place we store the correlated value.
                // this will later get sent to the sender.
                t1Val[i]
                    = code[i]
                    ^ t0Val[i]
                    ^ t1Val[i];
            }


#ifdef KKRT_SHA_HASH

        // now hash it to remove the correlation.
        RandomOracle  sha1(destSize);
        sha1.Update((u8*)mT0[otIdx].data(), mT0[otIdx].size() * sizeof(block));
        sha1.Final((u8*)dest);
#else
        s
        std::array<block, 10> aesBuff;
        mAesFixedKey.ecbEncBlocks(t0Val, mT0.stride(), aesBuff.data());

        val = ZeroBlock;
        for (u64 i = 0; i < mT0.stride(); ++i)
            val = val ^ aesBuff[i] ^ t0Val[i];
#endif
#ifndef NDEBUG
        // a debug check to mark this OT as used and ready to send.
        mT0[otIdx][0] = AllOneBlock;
#endif

    }

    void KkrtNcoOtReceiver::zeroEncode(u64 otIdx)
    {
#ifndef NDEBUG
        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extension");

        if (eq(mT0[otIdx][0], AllOneBlock))
            throw std::runtime_error("This otIdx has already been encoded");
#endif // !NDEBUG

        block* t0Val = mT0.data() + mT0.stride() * otIdx;
        block* t1Val = mT1.data() + mT0.stride() * otIdx;

        // This is here in the case that you done want to encode a message.
        // It s more efficient since we don't call SHA.
        for (u64 i = 0; i < mT0.stride(); ++i)
        {
            // reuse mT1 as the place we store the correlated value.
            // this will later get sent to the sender.
            t1Val[i]
                = t0Val[i]
                ^ t1Val[i];
        }

#ifndef NDEBUG
        // a debug check to mark this OT as used and ready to send.
        mT0[otIdx][0] = AllOneBlock;
#endif
    }

    void KkrtNcoOtReceiver::configure(
        bool maliciousSecure,
        u64 statSecParam,
        u64 inputBitCount)
    {
        if (maliciousSecure) throw std::runtime_error(LOCATION);
        if (inputBitCount > 128) throw std::runtime_error("currently only support up to 128 bit KKRT inputs. Can be extended on request" LOCATION);

        mInputByteCount = (inputBitCount + 7) / 8;
        auto count = 128 * 4;
        mGens.resize(count);

    }

    coproto::Proto KkrtNcoOtReceiver::sendCorrection(u64 sendCount)
    {
        //return coproto::Proto();

#ifndef NDEBUG
        // make sure these OTs all contain valid correction values, aka encode has been called.
        for (u64 i = mCorrectionIdx; i < mCorrectionIdx + sendCount; ++i)
            if (neq(mT0[i][0], AllOneBlock))
                throw std::runtime_error("This send request contains uninitialized OT. Call encode first...");
#endif

        coproto::span<u8> data((u8*)(mT1.data() + (mCorrectionIdx * mT1.stride())), mT1.stride() * sendCount * sizeof(block));
        mCorrectionIdx += sendCount;

        return coproto::send(data);
    }

#ifdef ENABLE_BOOST
    void KkrtNcoOtReceiver::sendCorrection(Channel & chl, u64 sendCount)
    {
#ifndef NDEBUG
        // make sure these OTs all contain valid correction values, aka encode has been called.
        for (u64 i = mCorrectionIdx; i < mCorrectionIdx + sendCount; ++i)
            if (neq(mT0[i][0], AllOneBlock))
                throw std::runtime_error("This send request contains uninitialized OT. Call encode first...");
#endif
        mHasPendingSendFuture = true;
        span<u8> data((u8*)(mT1.data() + (mCorrectionIdx * mT1.stride())), mT1.stride() * sendCount * sizeof(block));
        mCorrectionIdx += sendCount;
        mPendingSendFuture = chl.asyncSendFuture(data.data(), data.size());
    }
#endif

}
#endif