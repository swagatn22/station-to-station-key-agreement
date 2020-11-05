#include<bits/stdc++.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>
using namespace std;
#define ll unsigned long long

ll power(ll a, ll b, ll M) {
	ll ans = 1;
	while (b > 0) {
		if (b % 2 == 1)
			ans = (ans * a) % M;
		a = (a * a) % M;
		b /= 2;
	}
	return ans;
}

void error(const char *msg) {
	perror(msg);
	exit(1);
}

int main() {
	// signature verification part
	srand(time(NULL));
	ll p = 1217, q = 1213, K;         // K = session key
	ll N = p * q, phi = (p - 1) * (q - 1);
	ll e = 2;

	while (e < phi) {
		if (__gcd(e, phi) == 1)
			break;
		else
			e++;
	}

	ll k = 2, d = (k * phi + 1) / e;
	
	
	//
	//ll msg = 12345;                   // this msg is used to verify identity of Alice.
	//ll enc = power(msg, e, N);
	//


	// station-to-station key agreement part
	ll g = 112548, x, P = 1000000007;
	x = rand() % 10000;

	ll R1 = power(g, x, P), R2=0l;
	cout << "R1 = " << R1 << "\n";

	// authentication
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[255];

	portno = atoi("8786");
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("Error opening socket\n");

	server = gethostbyname("127.0.0.1");

	if (server == NULL)
		error("Error, no such host\n");

	bzero((char*) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char*)server->h_addr, (char*)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("Connection failed\n");

	ll sign, cert;

	k = 0;
	while (1) {
		if (k == 0) {
			cout << "Sending R1 = g^x(mod P) = " << R1 << " to B\n\n";

			bzero(buffer, 255);
			string temp = to_string(R1);
			for (ll i = 0; i < temp.size(); i++)
				buffer[i] = temp[i];
			buffer[temp.size()] = '\0';

			n = write(sockfd, buffer, strlen(buffer));
			if (n < 0)
				error("Error on Writing\n");
		}
		else if (k == 1) {
			bzero(buffer, 255);
			n = read (sockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			R2 = atoi(buffer);
			cout << "Recieved R2 = " << R2 << " from B\n";

			bzero(buffer, 255);
			n = read (sockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			sign = atoi(buffer);
			cout << "Recieved signature = " << sign << " from B\n";

			bzero(buffer, 255);
			n = read (sockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			cert = atoi(buffer);
			cout << "Recieved B's public key = " << cert << " from B\n\n";

			K = power(R2, x, P);
		}
		else if (k == 2) {
			ll dec = power(sign, cert, N);
			if (dec%N == R1%N) {
				cout << "Bob verified\n";


				//R2 on line 106
				ll msg = R2;                   // this msg is used to verify identity of Alice.
				ll enc = power(msg, d, N);

				//

				bzero(buffer, 255);
				string temp = to_string(enc);
				for (int i = 0; i < temp.size(); i++)
					buffer[i] = temp[i];
				buffer[temp.size()] = '\0';

				cout << "Sending signature(Signed R2 with d) = " << enc << " to B\n";
				n = write(sockfd, buffer, strlen(buffer));

				if (n < 0)
					error("Error on writing\n");

				bzero(buffer, 255);
				temp = to_string(e);
				for (int i = 0; i < temp.size(); i++)
					buffer[i] = temp[i];
				buffer[temp.size()] = '\0';

				cout << "Sending A's public key to B = " << e << " to B\n\n";
				n = write(sockfd, buffer, strlen(buffer));

				if (n < 0)
					error("Error on writing\n");
			}
			else {
				cout << "Unknown Sender\n";
				break;
			}
		}
		else if (k == 3) {
			bzero(buffer, 255);
			n = read (sockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			ll session_key = atoi(buffer);

			if (session_key == K) {
				cout << "Session Key verified...Now Chat...\n\n";
			}
			else {
				cout << "Session Key NOT verified\n";
				break;
			}
		}
		else {
			cout << "You : ";
			fgets(buffer, 255, stdin);
			n = write(sockfd, buffer, strlen(buffer));
			if (buffer[0] == 'e')
				break;

			if (n < 0)
				error("Error on Writing\n");

			bzero(buffer, 255);
			n = read (sockfd, buffer, 255);

			cout << "B : " << buffer << endl;
			if (buffer[0] == 'e')
				break;
		}

		k++;
	}
	close(sockfd);
	return 0;
}