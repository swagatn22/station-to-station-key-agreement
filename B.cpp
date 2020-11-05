#include<bits/stdc++.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
using namespace std;
#define ll unsigned long long

ll power(ll a, ll b, ll M) {
	ll ans = 1;
	while (b > 0)
	{
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
	srand (time(NULL));

	ll p = 1217, q = 1213, K;           // K = session key
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
	//ll msg = 54321;                   // this msg is used to verify identity of Bob.
	//ll enc = power(msg, e, N);
	//
	
	// station-to-station key agreement part
	ll g = 112548, y, P = 1000000007;
	y = rand() % 10000;

	ll R1=0l, R2 = power(g, y, P);
	cout << "R2 = " << R2 << "\n";

	// socket establishment
	int sockfd, newsockfd, portno, n, newsockfd1;
	char buffer[255];

	struct sockaddr_in serv_addr, cli_addr;
	socklen_t clilen;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);         // return file descriptor

	bzero((char*)&serv_addr, sizeof(serv_addr));      // clears buffers
	portno = atoi("8786");                            // convert character long longo string

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("Binding failed\n");

	listen(sockfd, 2);                               // max two connections at a time
	clilen = sizeof(cli_addr);

	newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);

	if (newsockfd < 0)
		error("Error on accept\n");

	ll sign, cert;

	k = 0;
	while (1) {
		if (k == 0) {
			bzero(buffer, 255);
			n = read(newsockfd, buffer, 255);

			if (n < 0)
				error("Error on reading\n");

			R1 = stoi(buffer);
			cout << "Recieved R1 = " << R1 << " from A\n\n";
			K = power(R1, y, P);
		}
		else if (k == 1) {
			bzero(buffer, 255);
			string temp = to_string(R2);
			for (int i = 0; i < temp.size(); i++){
				buffer[i] = temp[i];
				//cout<<buffer[i]<<" ";
			}
			//cout<<endl;
			buffer[temp.size()] = '\0';

			cout << "Sending R2 = g^y(mod P) = " << R2 << " to A\n";
			n = write(newsockfd, buffer, strlen(buffer));

			if (n < 0)
				error("Error on writing\n");
			//

			ll msg = R1;                   // this msg is used to verify identity of Alice.
			ll enc = power(msg, d, N);


			//
			bzero(buffer, 255);
			temp = to_string(enc);
			for (int i = 0; i < temp.size(); i++)
				buffer[i] = temp[i];
			buffer[temp.size()] = '\0';

			cout << "Sending signature(signed R1 with d) = " << enc << " to A\n";
			n = write(newsockfd, buffer, strlen(buffer));

			if (n < 0)
				error("Error on writing\n");

			bzero(buffer, 255);
			temp = to_string(e);
			for (int i = 0; i < temp.size(); i++)
				buffer[i] = temp[i];
			buffer[temp.size()] = '\0';

			cout << "Sending B's public key = " << e << " to A\n\n";
			n = write(newsockfd, buffer, strlen(buffer));

			if (n < 0)
				error("Error on writing\n");
		}
		else if (k == 2) {
			bzero(buffer, 255);
			n = read (newsockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			sign = atoi(buffer);
			cout << "Recieved sign = " << sign << " from A\n";

			bzero(buffer, 255);
			n = read (newsockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			cert = atoi(buffer);
			cout << "Recieved A's public key = " << cert << " from A\n\n";
		}
		else if (k == 3) {
			ll dec = power(sign, cert, N);
			if (dec%N == R2%N) {
				cout << "Alice verified\n";

				bzero(buffer, 255);
				string temp = to_string(K);
				for (int i = 0; i < temp.size(); i++)
					buffer[i] = temp[i];
				buffer[temp.size()] = '\0';

				cout << "Sending session key = " << K << " to A\n\n";
				n = write(newsockfd, buffer, strlen(buffer));

				if (n < 0)
					error("Error on writing\n");
			}
			else {
				cout << "Unknown sender\n";
				break;
			}
		}
		else {
			bzero(buffer, 255);
			n = read (newsockfd, buffer, 255);
			if (n < 0)
				error("Error on reading\n");

			cout << "A : " << buffer << endl;
			if (buffer[0] == 'e')
				break;
			cout << "You : ";

			bzero(buffer, 255);
			fgets(buffer, 255, stdin);
			n = write(newsockfd, buffer, strlen(buffer));

			if (n < 0)
				error("Error on writing\n");

			if (buffer[0] == 'e')
				break;
		}

		k++;
	}

	close(newsockfd);
	close(sockfd);
	return 0;
}

