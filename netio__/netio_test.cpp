#include <boost/program_options.hpp>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <cryptoTools/Network/NetIO.h>

using namespace osuCrypto;
using namespace emp;
using namespace std;
namespace po = boost::program_options;

#define LIBOTE
//#define EMPTOOLS

#ifdef LIBOTE
void __Server(int party, unsigned int port, string server_ip, uint64_t num_thrds, uint64_t num_elems){
	osuCrypto::Timer time;

	IOService ios;
	Session ep(ios, server_ip, port, SessionMode::Server);
	Channel chl = ep.addChannel();
	chl.waitForConnection();

    vector<int64_t> data(num_elems);
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	prng.get(data.data(), data.size());
    
	auto s = time.setTimePoint("start");
	chl.send(data);
	auto e = time.setTimePoint("finish");
	auto milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Consec: " << milli << " ms" << endl;
    
	s = time.setTimePoint("start");
	for (uint64_t e = 0; e < num_elems; ++e)
		chl.send(&data[e], 1);
	e = time.setTimePoint("finish");
	milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Seperate: " << milli << " ms" << endl;

	chl.close();
	ep.stop();
	ios.stop();
}

void __Client(int party, unsigned int port, string server_ip, uint64_t num_thrds, uint64_t num_elems){
	osuCrypto::Timer time;

	IOService ios;
	Session ep(ios, server_ip, port, SessionMode::Client);
	Channel chl = ep.addChannel();
	chl.waitForConnection();

    vector<int64_t> data(num_elems);

	auto s = time.setTimePoint("start");
	chl.recv(data);
	auto e = time.setTimePoint("finish");
	auto milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Consec: " << milli << " ms" << endl;
    
	s = time.setTimePoint("start");
	for (uint64_t e = 0; e < num_elems; ++e)
		chl.recv(&data[e], 1);
	e = time.setTimePoint("finish");
	milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Seperate: " << milli << " ms" << endl;

	for (uint64_t t = 0; t < num_thrds; ++t)
		chl.close();
	ep.stop();
	ios.stop();
}
#else
#ifdef EMPTOOLS
void __Server(int party, unsigned int port, string server_ip, uint64_t num_thrds, uint64_t num_elems){
	osuCrypto::Timer time;

	NetIO* io = new NetIO(party==ALICE ? nullptr:server_ip.c_str(), port, true);
	io->set_nodelay();

    vector<int64_t> data(num_elems);
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	prng.get(data.data(), data.size());
    
	auto s = time.setTimePoint("start");
	io->send_data(&data[0], num_elems);
	auto e = time.setTimePoint("finish");
	auto milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Consec: " << milli << " ms" << endl;

	io->flush();
    
	s = time.setTimePoint("start");
	for (uint64_t e = 0; e < num_elems; ++e)
		io->send_data(&data[e], 1);
	e = time.setTimePoint("finish");
	milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Seperate: " << milli << " ms" << endl;

	io->flush();
}

void __Client(int party, unsigned int port, string server_ip, uint64_t num_thrds, uint64_t num_elems){
	osuCrypto::Timer time;

	NetIO* io = new NetIO(party==ALICE ? nullptr:server_ip.c_str(), port, true);
	io->set_nodelay();

    vector<int64_t> data(num_elems);

	auto s = time.setTimePoint("start");
	io->recv_data(&data[0], num_elems);
	auto e = time.setTimePoint("finish");
	auto milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Consec: " << milli << " ms" << endl;

	io->flush();
    
	s = time.setTimePoint("start");
	for (uint64_t e = 0; e < num_elems; ++e)
		io->recv_data(&data[e], 1);
	e = time.setTimePoint("finish");
	milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Seperate: " << milli << " ms" << endl;

	io->flush();
}
#else
void __Server(int party, unsigned int port, string server_ip, uint64_t num_thrds, uint64_t num_elems){
	osuCrypto::Timer time;

	IOService ios;
	NetIO io{party==ALICE ? nullptr:server_ip.c_str(), port, true};
	io.set_nodelay();

	Channel aChl{ios, new SocketAdapter<NetIO>(io)};
	aChl.waitForConnection();

    vector<int64_t> data(num_elems);
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	prng.get(data.data(), data.size());
    
	auto s = time.setTimePoint("start");
	aChl.send(data);
	auto e = time.setTimePoint("finish");
	auto milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Consec: " << milli << " ms" << endl;
    
	io.flush();

	s = time.setTimePoint("start");
	for (uint64_t e = 0; e < num_elems; ++e)
		aChl.send(&data[e], 1);
	e = time.setTimePoint("finish");
	milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Seperate: " << milli << " ms" << endl;

	io.flush();
	aChl.close();
	ios.stop();
}

void __Client(int party, unsigned int port, string server_ip, uint64_t num_thrds, uint64_t num_elems){
	osuCrypto::Timer time;

	IOService ios;
	NetIO io{party==ALICE ? nullptr:server_ip.c_str(), port, true};
	io.set_nodelay();

	Channel aChl(ios, new SocketAdapter<NetIO>(io));
	aChl.waitForConnection();

    vector<int64_t> data(num_elems);

	auto s = time.setTimePoint("start");
	aChl.recv(data);
	auto e = time.setTimePoint("finish");
	auto milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Consec: " << milli << " ms" << endl;
    
	io.flush();

	s = time.setTimePoint("start");
	for (uint64_t e = 0; e < num_elems; ++e)
		aChl.recv(&data[e], 1);
	e = time.setTimePoint("finish");
	milli = chrono::duration_cast<chrono::milliseconds>(e - s).count();
	cout << "Seperate: " << milli << " ms" << endl;

	io.flush();
	for (uint64_t t = 0; t < num_thrds; ++t)
		aChl.close();
	ios.stop();
}
#endif
#endif

int main(int argc, char** argv) {
	int party, port;
	string server_ip;
	uint64_t num_thrds, num_elems;
	
	po::options_description desc{"explore OT \nAllowed options"};
	desc.add_options()  //
	("help,h", "produce help message")  //
	("party,k", po::value<int>(&party)->default_value(1), "party id: 1 for garbler, 2 for evaluator")  //
	("port,p", po::value<int>(&port)->default_value(1234), "socket port")  //
	("server_ip,s", po::value<string>(&server_ip)->default_value("127.0.0.1"), "server'c IP.") //
	("thrds,t", po::value<uint64_t>(&num_thrds)->default_value(1), "number of threads") //
	("elems,e", po::value<uint64_t>(&num_elems)->default_value(8192), "inner dim");
	
	po::variables_map vm;
	try {
		po::parsed_options parsed = po::command_line_parser(argc, argv).options(desc).allow_unregistered().run();
		po::store(parsed, vm);
		if (vm.count("help")) {
			cout << desc << endl;
			return 0;
		}
		po::notify(vm);
	}catch (po::error& e) {
		cout << "ERROR: " << e.what() << endl << endl;
		cout << desc << endl;
		return -1;
	}

	if (party == emp::ALICE) __Server(party, port, server_ip, num_thrds, num_elems);
	else __Client(party, port, server_ip, num_thrds, num_elems);

    return 0;
}