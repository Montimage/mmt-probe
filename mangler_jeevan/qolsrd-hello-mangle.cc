#include <sys/socket.h>
#include <sys/un.h>
#include <iostream>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iomanip>

int main(int argc, char* argv[])
{
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " socket-path" << std::endl;
    return 1;
  }

  int		sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);

  if (sock == -1) {
    std::cerr << "socket(PF_UNIX, SOCK_SEQPACKET): " << strerror(errno)
	      << std::endl;
    return 1;
  }

  sockaddr_un	sun = { PF_UNIX, "" };

  if (strlen(argv[1]) + 1 > sizeof sun.sun_path) {
    std::cerr << "Path too long." << std::endl;
    return 1;
  }

  std::copy_n(argv[1], strlen(argv[1]), sun.sun_path);

  int		ret = bind(sock, reinterpret_cast<const sockaddr*>(&sun),
			   sizeof sun);//bind a name to a  socket

  if (ret == -1) {
    std::cerr << "bind(\"" << sun.sun_path << "\"): " << strerror(errno)
	      << std::endl;
    return 1;
  }

  ret = listen(sock, 1);// listen for socket connections and limit the queue of incoming connections

  if (ret == -1) {
    std::cerr << "listen(): " << strerror(errno) << std::endl;
    return 1;
  }

  int	s = accept(sock, nullptr, nullptr);// accepts new connection on a socket

  if (ret == -1) {
    std::cerr << "accept(): " << strerror(errno) << std::endl;
    return 1;
  }

  while (true) {
    char	buffer[4096];

    iovec	iov = { buffer, sizeof buffer }; //contains the address of the buffer and contains the length of the buffer

    msghdr	hdr = { nullptr, 0, &iov, 1, nullptr, 0, 0 }; //The msghdr structure is used to minimize the number of directly supplied parameters to the recvmsg() and sendmsg() functions

    ret = recvmsg(s, &hdr, 0); //It shall receive message from unconnectted or connected sockets and shall return the length of the message

    if (ret == -1) {
      if (errno == ECONNRESET)
	break;
      std::cerr << "recvmsg(): " << strerror(errno) << std::endl;
    }

    if (ret == 0)
      break;

    std::cout << "Mangled packet of\n" << iov.iov_len << " byte(s)" << std::endl;

    iov.iov_len = ret;
    std::cout << "Actual packet size\n" << iov.iov_len << " byte(s)" << std::endl;
    
    for (int i=0; i< ret;i++){
        std::cout << std::hex << std::uppercase << (int)buffer[i] << std::nouppercase << std::dec<< std::endl;
    }
    std::cout << "\n\n"; 
    
    std::cout << "Hello packet=="<<std::hex<<(int)buffer[46] << std::dec << std::endl;

    if ((int)buffer[46]==1){
    std::cout << "Changed buffer :Attacker\n" <<std::endl;
    buffer[70] = 191;//BF

        for (int i=0; i< ret;i++){
        std::cout << std::hex << std::uppercase << (int)buffer[i] << std::nouppercase << std::dec<< std::endl;
        }
    }
 

    ret = sendmsg(s, &hdr, 0);//send a message on a socket using a message structure

    std::cout << "Send to socket="<<ret<<"bytes"<<std::endl; 
    

    if (ret == -1) {
      std::cerr << "sendmsg(): " << strerror(errno) << std::endl;
    }
  }

  return 0;
}
