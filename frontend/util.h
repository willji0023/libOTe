#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 



#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Network/Channel.h>

#ifdef ENABLE_BOOST
void senderGetLatency(osuCrypto::Channel& chl);

void recverGetLatency(osuCrypto::Channel& chl);
void getLatency(osuCrypto::CLP& cmd);

void sync(osuCrypto::Channel& chl, Role role);
#endif

enum class Role
{
	Sender,
	Receiver
};