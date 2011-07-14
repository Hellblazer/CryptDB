#include "OPE.h"
#include "HGD.h"
#include "params.h"
#include "util.h"
#include "EDBClient.h"
#include <stdio.h>
#include "unistd.h"
#include "time.h"
#include "string.h"
#include "CryptoManager.h"
#include <iostream>
#include <istream>
#include <fstream>
#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <sys/wait.h>
#include "AccessManager.h"
#include "Connect.h"
#include "Equation.h"

#include "TestSinglePrinc.h"


using namespace std;

clock_t timeStart;
void startTimer () {
	timeStart = time(NULL);
}

// in msecs
double readTimer() {
	clock_t currentTime = time(NULL);
	//cout << "curr time " << currentTime << "timeStart " <<timeStart << "\n";
	//cout << "clocks per sec " << CLOCKS_PER_SEC << "\n";
	double res = (currentTime - timeStart) * 1000.0 ;
	return res;
}


void test_OPE() {

	cerr << "\n OPE test started \n";

	const unsigned int  OPEPlaintextSize = 32;
	const unsigned int OPECiphertextSize = 128;

	unsigned char key[AES_KEY_SIZE/bitsPerByte] = {158, 242, 169, 240, 255, 166, 39, 177, 149, 166, 190, 237, 178, 254, 187, 40};

	cerr <<"Key is "; myPrint(key, AES_KEY_SIZE/bitsPerByte); cerr << "\n";

	OPE * ope = new OPE((const char *) key, OPEPlaintextSize, OPECiphertextSize);

	unsigned char plaintext[OPEPlaintextSize/bitsPerByte] = {74, 95, 221, 84};
	string plaintext_s = string((char *) plaintext, OPEPlaintextSize/bitsPerByte);

	string ciphertext = ope->encrypt(plaintext_s);
	string decryption = ope->decrypt(ciphertext);


	cerr << "Plaintext is "; myPrint(plaintext_s); cerr << "\n";

	cerr << "Ciphertext is "; myPrint(ciphertext); cerr << "\n";

	cerr << "Decryption is "; myPrint(decryption); cerr << "\n";

	myassert(plaintext_s == decryption, "OPE test failed \n");

	cerr << "OPE Test Succeeded \n";

	unsigned int tests = 100;
	cerr << "Started " << tests << " tests \n ";

	clock_t encTime = 0;
	clock_t decTime = 0;
	clock_t currTime;
	time_t startTime = time(NULL);
	for (unsigned int i = 0; i < tests ; i++) {

		string ptext = randomBytes(OPEPlaintextSize/bitsPerByte);
		currTime = clock();
		string ctext =  ope->encrypt(ptext);
		encTime += clock() - currTime;
		currTime = clock();
		string decryption = ope->decrypt(ctext);
		decTime += clock() - currTime;
	}
	time_t endTime = time(NULL);
	cout << "(time): encrypt/decrypt take  " << (1.0 * (endTime-startTime))/(2.0*tests) << "s \n";
	cout << "encrypt takes on average " << (encTime*1000.0)/(1.0*CLOCKS_PER_SEC*tests) << "ms \n";
	cout << "decrypt takes on average " << (decTime*1000.0)/(1.0*CLOCKS_PER_SEC*tests) << "ms \n";


}

void evaluate_AES(int argc, char ** argv) {

	if (argc!=2) {
		cout << "usage ./test noTests \n";
		exit(1);
	}

	unsigned int notests = 10;

	string key = randomBytes(AES_KEY_SIZE/bitsPerByte);
	string ptext = randomBytes(AES_BLOCK_SIZE/bitsPerByte);

	AES_KEY aesKey;
	AES_set_encrypt_key((const uint8_t *) key.c_str(), AES_KEY_SIZE, &aesKey);

	timeval startTime, endTime;

	unsigned int tests = 1024*1024;

	for (unsigned int j = 0; j < notests; j++) {
		gettimeofday(&startTime, NULL);

		for (unsigned int i = 0; i < tests; i++) {
			unsigned char ctext[AES_BLOCK_SIZE/bitsPerByte];
			AES_encrypt((const uint8_t *) ptext.c_str(), ctext, &aesKey);
			ptext = string((char *) ctext, AES_BLOCK_BYTES);
		}

		gettimeofday(&endTime, NULL);

		cerr << (tests*16.0)/(1024*1024) << "  " << timeInSec(startTime, endTime) << " \n"; //MB sec
		tests = tests * 1.2;
	}
	cout << "result " << ptext  << "\n";

}

void test_HGD() {
	unsigned int len = 16; //bytes
	unsigned int bitsPrecision = len * bitsPerByte + 10;
	ZZ K = ZZFromString(randomBytes(len));
	ZZ N1 = ZZFromString(randomBytes(len));
	ZZ N2 = ZZFromString(randomBytes(len));
	ZZ SEED = ZZFromString(randomBytes(len));

	ZZ sample = HGD(K, N1, N2, SEED, len*bitsPerByte, bitsPrecision);

	cerr << "N1 is "; myPrint(BytesFromZZ(N1,len), len); cerr << "\n";
	cerr << "N2 is "; myPrint(BytesFromZZ(N2,len), len); cerr << "\n";
	cerr << "K is "; myPrint(BytesFromZZ(K, len), len); cerr << "\n";
	cerr << "HGD sample is "; myPrint(BytesFromZZ(sample, len), len); cerr << "\n";

	unsigned int tests = 1000;
	cerr << " Started " << tests << " tests \n";

	clock_t totalTime = 0; //in clock ticks

	for (unsigned int i = 0 ; i< tests ;i++) {
		K = N1+ N2+1;
		while (K > N1+N2) {
			cerr << "test " << i << "\n";
			K = ZZFromString(randomBytes(len));
			N1 = ZZFromString(randomBytes(len));
			N2 = ZZFromString(randomBytes(len));
			SEED = ZZFromString(randomBytes(len));
		}

		clock_t currentTime = clock();
		sample = HGD(K, N1, N2, SEED, len*bitsPerByte, bitsPrecision);

		totalTime += clock() - currentTime;
	}

	cerr << "average milliseconds per test is " << (totalTime * 1000.0) / (tests * CLOCKS_PER_SEC) << "\n";
}
/*
void test_EDBClient_noSecurity() {
    EDBClient  e =  EDBClient((char *)"dbname = postgres", false);

    PGresult * res = e.execute("SELECT * FROM pg_database ;");

    int nFields = PQnfields(res);
    for (int i = 0; i < nFields; i++)
        printf("%-15s", PQfname(res, i));
    printf("\n\n");
 */
/* next, print out the rows */
/*    for (int i = 0; i < PQntuples(res); i++)
    {
        for (int j = 0; j < nFields; j++)
            printf("%-15s", PQgetvalue(res, i, j));
        printf("\n");
    }

    PQclear(res);



}*/



void evaluateMetrics(int argc, char ** argv) {

	if (argc != 4) {
		printf("usage: ./test noRecords tests haveindex?(0/1) ");
		exit(1);
	}


	unsigned int noRecords = atoi(argv[1]);
	unsigned int tests = atoi(argv[2]);

	time_t timerStart, timerEnd;


	EDBClient * cl = new EDBClient("localhost", "raluca", "none", "cryptdb");

	cl->execute("CREATE TABLE testplain (field1 int, field2 int, field3 int);");
	cl->execute("CREATE TABLE testcipher (field1 varchar(16), field2 varchar(16), field3 varchar(16));");


	timerStart = time(NULL);
	//populate both tables with increasing values
	for (unsigned int i = 0; i < noRecords; i++) {
		string commandPlain = "INSERT INTO testplain VALUES (";
		string value = StringFromVal(i);
		commandPlain = commandPlain + value + ", " + value + "," + value + ");";

		cl->execute(commandPlain.c_str());

	}
	timerEnd = time(NULL);
	printf("insert plain average time %f ms \n", (1000.0 * (timerEnd-timerStart))/(noRecords*1.0));


	timerStart = time(NULL);
	for (unsigned int i = 0; i < noRecords; i++) {
		string commandCipher = "INSERT INTO testcipher VALUES (";
		string valueBytes ="'" + StringFromVal(i, AES_BLOCK_BITS/bitsPerByte) + "'";

		commandCipher = commandCipher + valueBytes + ", " + valueBytes + ", " + valueBytes+ ");";
		cl->execute(commandCipher.c_str());

	}
	timerEnd = time(NULL);
	printf("insert cipher average time %f ms \n", (1000.0 * (timerEnd-timerStart))/(noRecords*1.0));


	if (atoi(argv[3]) == 1) {
		cout << "create index";
		cl->execute("CREATE INDEX indplain ON testplain (field1) ;");
		cl->execute("CREATE INDEX indcipher ON testcipher (field1) ;");
	}

	timerStart = time(NULL);
	//equality selection
	for (unsigned int i = 0; i < tests; i++) {
		int j = rand() % noRecords;
		string commandPlain = "SELECT * FROM testplain WHERE field1 = ";
		string value = StringFromVal(j);
		commandPlain += value  + ";";
		//cout << "CL " << clock() << "\n";
		cl->execute(commandPlain.c_str());

	}
	timerEnd = time(NULL);

	printf("select plain time %f ms \n", (1000.0 * (timerEnd-timerStart))/(tests*1.0));



	timerStart = time(NULL);
	//equality selection
	for (unsigned int i = 0; i < tests; i++) {
		int j = rand() % noRecords;
		string commandCipher = "SELECT * FROM testcipher WHERE field1 = ";
		string valueBytes = "'" + StringFromVal(j, AES_BLOCK_BITS/bitsPerByte) + "'";

		commandCipher = commandCipher + valueBytes + ";";
		cl->execute(commandCipher.c_str());

	}
	timerEnd = time(NULL);

	printf("cipher average time %f ms \n", (1000.0*(timerEnd-timerStart))/(tests*1.0));

	/*
    timerStart = time(NULL);
    //inequality selection
    for (int i = 0; i < tests; i++) {
	int leftJ = rand() % noRecords;
	//int rightJ = rand() % noRecords;

	//if (leftJ > rightJ) {
	//    int aux = leftJ;
	//    leftJ = rightJ;
	//    rightJ = aux;
	//}
	int rightJ = leftJ + (rand() % 50);

	string commandPlain = "SELECT * FROM testplain WHERE field1 > ";
	string leftJBytes = StringFromVal(leftJ);
	string rightJBytes = StringFromVal(rightJ);

	commandPlain = commandPlain + leftJBytes + " AND field1 < " + rightJBytes + ";";

	cl->execute(commandPlain.c_str());
    }
    timerEnd = time(NULL);
    printf("range select plain %f ms \n", (1000.0*(timerEnd-timerStart))/(tests*1.0)); 
	 */
	/*
    timerStart = time(NULL);
    //inequality selection
    for (int i = 0; i < tests; i++) {
	int leftJ = rand() % noRecords;
	//int rightJ = rand() % noRecords;

	//if (leftJ > rightJ) {
	//    int aux = leftJ;
	//    leftJ = rightJ;
	//    rightJ = aux;
	//}
	int rightJ = leftJ + (rand() % 50);

	string commandCipher = "SELECT * FROM testcipher WHERE field1 > ";
	string leftJBytes = "'" + StringFromVal(leftJ, AES_BLOCK_BITS/bitsPerByte) + "'";
	string rightJBytes = "'" + StringFromVal(rightJ, AES_BLOCK_BITS/bitsPerByte) + "'";

	commandCipher = commandCipher + leftJBytes + " AND field1 < " + rightJBytes + ";";

	cl->execute(commandCipher.c_str());
    }
    timerEnd = time(NULL);
    printf("range select cipher %f ms \n", (1000.0*(timerEnd-timerStart))/(tests*1.0)); 
	 */

	cl->execute("DROP TABLE testplain;");
	cl->execute("DROP TABLE testcipher;");

}

//tests protected methods of EDBClient
class tester: public EDBClient {
public:
	tester(string dbname, const string &masterKey): EDBClient("localhost", "raluca", "none", dbname, masterKey) {}
	tester(string dbname): EDBClient("localhost", "raluca", "none", dbname) {};
	void testClientParser();
	void loadData(EDBClient * cl, string workload, int logFreq);

	//void testMarshallBinary();
};

void tester::testClientParser() {


	list<string> queries = list<string>();
	//queries.push_back(string("CREATE TABLE people (id integer, age integer, name integer);") + '\0');
	queries.push_back(string("CREATE TABLE city (name integer, citizen integer);") + '\0');
	queries.push_back(string("CREATE TABLE emp (id integer, name text, age integer, job text);")+'\0');
	//queries.push_back(string("SELECT city.citizen FROM people, city WHERE city.citizen = people.name ; ") + '\0');
	//queries.push_back(string("INSERT INTO people VALUES (5, 23, 34);") + '\0');
	//queries.push_back(string("INSERT INTO city VALUES (34, 24);") + '\0');
	//queries.push_back(string("SELECT people.id FROM people WHERE people.id = 5 AND people.id = people.age ;") + '\0');
	//queries.push_back(string("DROP TABLE people;")+'\0');

	list<int> expectedCount = list<int>();
	expectedCount.push_back(1);
	expectedCount.push_back(1);
	expectedCount.push_back(4);
	expectedCount.push_back(2);
	expectedCount.push_back(4);
	expectedCount.push_back(1);


	list<string> expected = list<string>();

	expected.push_back(string("CREATE TABLE table0 (  field0DET integer, field0OPE bigint, field1DET integer, field1OPE bigint, field2DET integer, field2OPE bigint );") + '\0');
	expected.push_back(string("CREATE TABLE table1 (  field0DET integer, field0OPE bigint, field1DET integer, field1OPE bigint );") + '\0');
	expected.push_back(string("UPDATE table1 SET field1DET = DECRYPT(0);") + '\0');
	expected.push_back(string("UPDATE table0 SET field2DET = DECRYPT(0);") + '\0');
	expected.push_back(string("UPDATE table1 SET field1DET = EQUALIZE(0);") + '\0');
	expected.push_back(string("SELECT  table1.field1DET FROM  table0, table1 WHERE  table1.field1DET  =  table0.field2DET ;") + '\0');
	expected.push_back(string("UPDATE table1 SET field1DET = 5;") + '\0');
	expected.push_back(string("UPDATE table1 SET field1OPE = 5;") + '\0');
	expected.push_back(string("UPDATE table0 SET field0DET = DECRYPT(0);") + '\0');
	expected.push_back(string("UPDATE table0 SET field1DET = DECRYPT(0);") + '\0');
	expected.push_back(string("UPDATE table0 SET field0DET = EQUALIZE(0);") + '\0');
	expected.push_back(string("SELECT  table0.field0DET FROM  table0 WHERE  table0.field0DET  = 5 AND  table0.field0DET  =  table0.field1DET ;") + '\0');
	expected.push_back(string("DROP TABLE table0;") + '\0');


	list<string>::iterator it = queries.begin();

	for (; it != queries.end();it++) {//TODO: check against expected...at this point is more of a manual check
		list<const char*> response = rewriteEncryptQuery(it->c_str());
		fprintf(stderr, "query issued/response: \n%s \n", it->c_str());
		myPrint(response);
		fprintf(stderr, "\n");
	}

	exit();
	cerr << "TEST TRANSLATOR PASSED \n" ;
}


void testCryptoManager() {

	string masterKey = randomBytes(AES_KEY_BYTES);
	CryptoManager * cm = new CryptoManager(masterKey);

	cerr << "TEST CRYPTO MANAGER \n";

	//test marshall and unmarshall key
	string m = cm->marshallKey(masterKey);
	cerr << " master key is ";
	myPrint(masterKey);
	cerr << " and marshall is " << m << "\n";
	string masterKey2 = cm->unmarshallKey(m);

	myassert(masterKey == masterKey2, "marshall test failed");


	cerr << " key for field1";
	myPrint(cm->getKey("field1", SEMANTIC_OPE));
	cerr << "\n key for table5.field12OPE";
	myPrint(cm->getKey("table5.field12OPE", SEMANTIC_OPE));


	//test SEM
	AES_KEY * aesKey = cm->get_key_SEM(masterKey);
	uint64_t salt = 3953954;
	uint32_t value = 5;
	uint32_t eValue = cm->encrypt_SEM(value, aesKey, salt);
	cerr << "\n sem encr of " << value << " is " << eValue << "with salt " << salt << " and decr of encr is " << cm->decrypt_SEM(eValue, aesKey, salt) <<"\n";
	myassert(cm->decrypt_SEM(eValue, aesKey, salt) == value, "decrypt of encrypt does not return value");

	cerr << "SEMANTIC " << SEMANTIC_OPE << "\n";

	uint64_t value2 = 10;
	uint64_t eValue2 = cm->encrypt_SEM(value2, aesKey, salt);
	cerr << "sem encr of " << value2 << " is " << eValue2 << " and signed is " << (int64_t) eValue2 << "\n";
	myassert(cm->decrypt_SEM(eValue2, aesKey, salt) == value2, "decrypt of encrypt does not return correct value for uint64_t");

	cerr << "0, " << (int64_t) eValue2 << ", " << m << ", " << salt << "\n";

	OPE * ope = cm->get_key_OPE(masterKey);
	uint64_t eOPE = cm->encrypt_OPE(value, ope);
	cerr << "encryption is eOPE " << eOPE << " \n";
	myassert(cm->decrypt_OPE(eOPE, ope) == value, "ope failed");

	cerr << "TEST CRYPTO MANAGER PASSED \n";




}

const uint64_t mkey = 113341234;

void evalImproveSummations() {
	string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
	string host = "localhost";
	string user = "root";
	string db = "mysql";
	string pwd = "letmein";
	cerr << "connecting to host " << host << " user " << user << " pwd " << pwd << " db " << db << endl;
	EDBClient * cl = new EDBClient(host, user, pwd, db, masterKey);
	cl->VERBOSE = true;

	cl->execute("CREATE TABLE test_table (id enc integer,  name enc text)");
	unsigned int no_inserts = 100;
	unsigned int no_sums = 20;

	for (unsigned int i = 0; i < no_inserts; i++) {
		cl->execute(getCStr(string("INSERT INTO test_table VALUES (") + StringFromVal(i) + " , 'ana');"));
	}

	startTimer();
	for (unsigned int i = 0 ; i < no_sums; i++) {
		cl->execute("SELECT sum(id) FROM test_table;");
	}
	double time = readTimer();

	cerr << "time per sum: " << time/(1.0*no_sums) << " ms \n";

}

void interactiveTest() {

	cout << "\n ---------   CryptDB ---------- \n \n";

	cout << "To exit, hit \\q\n";


	string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
	string host = "localhost";
	string user = "root";
	string db = "mysql";
	string pwd = "letmein";
	cerr << "connecting to host " << host << " user " << user << " pwd " << pwd << " db " << db << endl;
	EDBClient * cl = new EDBClient(host, user, pwd, db, masterKey);
	cl->VERBOSE = true;

	streamsize len = 100;
	char * command = new char[len];

	for (;;) {

		cout << "CryptDB=# ";
		cin.getline(command, len);
		if (cin.eof())
			break;

		string commandS = string(command);

		if (commandS.compare("\\q") == 0) {
			break;
		} else if (commandS.compare("load cryptapp") == 0) {
			cl->execute("CREATE TABLE users (id integer accessto uname, uname text givespsswd); ");
			cl->execute("CREATE TABLE info (id integer equals users.id , creditcard integer encfor id); ");
			cl->execute("INSERT INTO activeusers VALUES ('alice', 'secretA');");
			cl->execute("INSERT INTO activeusers VALUES ('bob', 'secretB');");
			cl->execute("INSERT INTO activeusers VALUES ('chris', 'secretC');");
			cl->execute("INSERT INTO activeusers VALUES ('dan', 'secretD');");
			cl->execute("INSERT INTO users VALUES (1, 'alice');");
			cl->execute("INSERT INTO users VALUES (2, 'bob');");
			cl->execute("INSERT INTO users VALUES (3, 'chris');");
			cl->execute("INSERT INTO users VALUES (4, 'dan');");
			cl->execute("INSERT INTO info VALUES (1, 111);");
			cl->execute("INSERT INTO info VALUES (2, 222);");
			cl->execute("INSERT INTO info VALUES (3, 333);");
			cl->execute("INSERT INTO info VALUES (4, 444);");
		} else if (commandS.compare("load people;") == 0) {
			int noInserts = 15;
			for (int i = 0; i < noInserts; i++) {
				unsigned int val1 = rand() % 10;
				unsigned int val2 = rand() % 10;
				string qq = "INSERT INTO people VALUES ( " + marshallVal(val1) + ", " + marshallVal(val2) + ");";
				cl->execute(getCStr(qq));
			}
		} else if (commandS.compare("load all emp;") == 0) {
			cl->execute("CREATE TABLE emp (id integer, jobid integer);");

			int noInserts = 20;
			for (int i = 0; i < noInserts; i++) {
				unsigned int val1 = rand() % 10;
				unsigned int val2 = rand() % 10;
				string qq = "INSERT INTO emp VALUES ( " + marshallVal(val1) + ", " + marshallVal(val2) + ");";
				cl->execute(getCStr(qq));
			}
		} else if (commandS.find("login") == 0) {
			list<string> words = parse(getCStr(commandS), delimsStay, delimsGo, keepIntact);
			list<string>::iterator wordsIt = words.begin();
			wordsIt++;
			string uname = getVal(wordsIt);
			string p = getVal(wordsIt);
			string query = "INSERT INTO activeusers VALUES ('" + uname + "' , '" + p + "' );" + '\0';
			cl->execute(getCStr(query));
		} else if (commandS.find("logout") == 0) {
			list<string> words = parse(getCStr(commandS), delimsStay, delimsGo, keepIntact);
			list<string>::iterator wordsIt = words.begin();
			wordsIt++;
			string uname = getVal(wordsIt);
			string query = "DELETE FROM activeusers WHERE uname = '" + uname + "';" + '\0';
			cl->execute(getCStr(query));
		} else if (commandS.compare("debug;") == 0) {
			//assert_s(cl->execute(), "failed");

			//debugging of DECRYPTFIRST mode

			//cl->plain_execute("DROP TABLE IF EXISTS hi;");
			//assert_s(cl->execute("CREATE TABLE hi (id enc integer, name text);"), "failed");
			//	assert_s(cl->execute("INSERT INTO hi VALUES (3, '5');"), "failed");
			//	assert_s(cl->execute("SELECT * FROM hi;"), "failed");
			//	assert_s(cl->execute("SELECT id, name AS n FROM hi WHERE id = 3;"), "failed");
			//	assert_s(cl->execute("SELECT * FROM hi WHERE id > 2;"), "failed");
			//assert_s(cl->execute("SELECT * FROM hi;"), "failed");


			//GENERAL MULTI-KEY DEBUGGING

			 /*
			cl->plain_execute("DROP TABLE IF EXISTS t1, users, pwdcryptdb__users, cryptdb_public, cryptdb_active0;");
			assert_s(cl->execute("CREATE TABLE t1 (id integer, post encfor id det text, age encfor id ope bigint);"), "failed");
			assert_s(cl->execute("CREATE TABLE users (id equals t1.id integer, username givespsswd id text);"), "failed");
			assert_s(cl->execute("COMMIT ANNOTATIONS;"), "issue when creating tables");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice', 'secretalice');").c_str()), "failed to log in user");
			assert_s(cl->execute((string("DELETE FROM ") + PWD_TABLE_PREFIX + "users  WHERE username = 'alice';").c_str()), "failed to logout user");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice', 'secretalice');").c_str()), "failed to log in user");
			assert_s(cl->execute("INSERT INTO users VALUES (1, 'alice');"), "failed to add alice in users table");
			assert_s(cl->execute("INSERT INTO t1 VALUES (1, 'there you go', 23);"), "failed to insert");
			assert_s(cl->execute("SELECT * FROM t1;"), "failed");

			assert_s(cl->execute("SELECT post FROM t1 WHERE id = 1 AND age = 23;"), "failed");
			assert_s(cl->execute("UPDATE t1 SET post = 'hello!' WHERE age > 22 AND id = 1;"), "failed");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('raluca', 'secretraluca');").c_str()), "failed to log in user");
			assert_s(cl->execute("INSERT INTO users VALUES (2, 'raluca');"), "failed");
			assert_s(cl->execute("INSERT INTO t1 VALUES (2, 'my text', 5);"), "failed");
			*/


			//PRIVATE MESSAGES EXAMPLE
			cl->plain_execute("DROP TABLE IF EXISTS users, msgs, privmsg;");
			assert_s(cl->execute("CREATE TABLE msgs (msgid equals privmsg.msgid integer, msgtext encfor msgid text);"), "failed");
			assert_s(cl->execute("CREATE TABLE privmsg (msgid integer, recid equals users.userid hasaccessto msgid integer, senderid hasaccessto msgid integer);"), "failed");
			assert_s(cl->execute("CREATE TABLE users (userid equals privmsg.senderid integer, username givespsswd userid text);"), "failed");
			assert_s(cl->execute("COMMIT ANNOTATIONS;"), "issue when creating tables");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice', 'secretalice');").c_str()), "failed to log in user");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob', 'secretbob');").c_str()), "failed to log in user");
			assert_s(cl->execute("INSERT INTO users VALUES (1, 'alice');"), "failed");
			assert_s(cl->execute("INSERT INTO users VALUES (2, 'bob');"), "failed");
			assert_s(cl->execute("INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2);"), "failed to send msg");
			assert_s(cl->execute("INSERT INTO msgs  VALUES (1, 'hello world');"), "failed to insert msg");
			assert_s(cl->execute("SELECT msgtext from msgs WHERE msgid = 1;"), "failed");
			assert_s(cl->execute("SELECT msgtext from msgs, privmsg, users WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid;"), "failed");

			//private messages without orphans
			/* cl->plain_execute("DROP TABLE IF EXISTS users, msgs, privmsg;");
			assert_s(cl->execute("CREATE TABLE msgs (msgid equals privmsg.msgid integer, msgtext encfor msgid text);"), "failed");
			assert_s(cl->execute("CREATE TABLE privmsg (msgid integer, recid equals users.userid hasaccessto msgid integer, senderid hasaccessto msgid integer);"), "failed");
			assert_s(cl->execute("CREATE TABLE users (userid equals privmsg.senderid integer, username givespsswd userid text);"), "failed");
			assert_s(cl->execute("COMMIT ANNOTATIONS;"), "issue when creating tables");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice', 'secretalice');").c_str()), "failed to log in user");
			assert_s(cl->execute((string("INSERT INTO ") + PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob', 'secretbob');").c_str()), "failed to log in user");
			assert_s(cl->execute("INSERT INTO users VALUES (1, 'alice');"), "failed");
			assert_s(cl->execute("INSERT INTO users VALUES (2, 'bob');"), "failed");
			assert_s(cl->execute("INSERT INTO privmsg (msgid, recid, senderid) VALUES (1, 1, 2);"), "failed to send msg");
			assert_s(cl->execute("INSERT INTO msgs  VALUES (1, 'hello world');"), "failed to insert msg");
			assert_s(cl->execute("SELECT msgtext from msgs WHERE msgid = 1;"), "failed");
			assert_s(cl->execute("SELECT msgtext from msgs, privmsg, users WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid;"), "failed");
			*/

			//USERID, GROUP, FORUM, SQL PRED EXAMPLE
			//	cl->plain_execute("DROP TABLE IF EXISTS users, usergroup, groupforum, forum;");
			//	assert_s(cl->execute("CREATE TABLE users (userid integer, username givespsswd userid text);"), "failed");
			//	assert_s(cl->execute("CREATE TABLE usergroup (userid equals users.userid hasaccessto groupid integer, groupid integer);"), "failed");
			//	assert_s(cl->execute("CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid hasaccessto forumid if test(optionid) integer, optionid integer);"), "failed");
			//	assert_s(cl->execute("CREATE TABLE forum (forumid integer, forumtext encfor forumid text);"), "failed");
			//	assert_s(cl->plain_execute("DROP FUNCTION IF EXISTS test;"), "failed");
			//	assert_s(cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20;"), "failed");
			//
			//	//Alice is in group 1, Bob in group 2 and Chris is in group 1 and group 2
			//	//group 1 can see the forum text, group 2 cannot
			//	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('alice', 'secretalice');"), "failed to log in user");
			//	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('bob', 'secretbob');"), "failed to log in user");
			//	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('chris', 'secretbob');"), "failed to log in user");
			//
			//	assert_s(cl->execute("INSERT INTO users (username) VALUES ('alice');"), "failed");
			//	assert_s(cl->execute("INSERT INTO users (username) VALUES ('bob');"), "failed");
			//	assert_s(cl->execute("INSERT INTO users (username) VALUES ('chris');"), "failed");
			//
			//	assert_s(cl->execute("INSERT INTO usergroup VALUES (1, 1);"), "failed");
			//	assert_s(cl->execute("INSERT INTO usergroup VALUES (2, 2);"), "failed");
			//	assert_s(cl->execute("INSERT INTO usergroup VALUES (3, 1);"), "failed");
			//	assert_s(cl->execute("INSERT INTO usergroup VALUES (3, 2);"), "failed");
			//
			//
			//	assert_s(cl->execute("INSERT INTO groupforum VALUES (1, 1, 14);"), "failed");
			//	assert_s(cl->execute("INSERT INTO groupforum VALUES (1, 1, 20);"), "failed");
			//	assert_s(cl->execute("INSERT INTO groupforum VALUES (1, 2, 2);"), "failed");
			//	assert_s(cl->execute("INSERT INTO groupforum VALUES (1, 2, 0);"), "failed");
			//
			//	assert_s(cl->execute("INSERT INTO forum (forumtext) VALUES ('success--you can see forum text');"), "failed");
			//
			//	//all users log out, then each log in to have their permissions tested
			//	assert_s(cl->execute("DELETE FROM "psswdtable" WHERE  username = 'alice';"), "failed");
			//	assert_s(cl->execute("DELETE FROM "psswdtable" WHERE  username = 'bob';"), "failed");
			//	assert_s(cl->execute("DELETE FROM "psswdtable" WHERE  username = 'chris';"), "failed");
			//
			//
			//	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('alice', 'secretalice');"), "failed to log in user");
			//
			//	assert_s(cl->execute("SELECT forumtext from forum  WHERE forumid  = 1;"), "Alice should succeed");
			//
			//	assert_s(cl->execute("DELETE FROM "psswdtable" WHERE  username = 'alice';"), "failed");
			//	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('bob', 'secretbob');"), "failed to log in user");
			//
			//	assert_s(cl->execute("DELETE FROM "psswdtable" WHERE  username = 'bob';"), "failed");
			//	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('chris', 'secretchris');"), "failed to log in user");
			//
			//	assert_s(cl->execute("SELECT forumtext from forum  WHERE forumid  = 1;"), "chris should succeed");

			//multi-key debugging

			/*	cl->plain_execute("DROP TABLE IF EXISTS hi, try, bye;");
			//some single key debugging
			assert_s(cl->execute("CREATE TABLE hi (id integer, age enc integer, name enc text);"), "q failed");
			assert_s(cl->execute("INSERT INTO hi VALUES (3, 9, 'raluca');"), "q failed");
			assert_s(cl->execute("SELECT * FROM hi WHERE id = 4;"), "q failed");

			assert_s(cl->execute("UPDATE hi SET age = age + 1, name = 'ana' WHERE id = 3;"), "q failed");

			assert_s(cl->execute("CREATE TABLE try (id enc integer, age integer);"), "q failed");
			assert_s(cl->execute("INSERT INTO try VALUES (5, 6);"), "q failed");
			assert_s(cl->execute("SELECT u.*, v.* from hi u, try AS v;"), "q failed");

			cl->outputOnionState();

			assert_s(cl->execute("SELECT * FROM (hi u, try AS v);"),"q failed");

			assert_s(cl->execute("SELECT MAX(id) AS h, MIN(id) as ll FROM try;"),"failed max");

			assert_s(cl->execute("SELECT u.id FROM try t LEFT JOIN try u ON u.id = t.id;"),"");

			assert_s(cl->execute("SELECT * FROM try WHERE id = 5"),"");

			assert_s(cl->execute("SELECT * FROM try WHERE age IN (0,9);"),"");


			assert_s(cl->execute("INSERT INTO try VALUES (3, 9), (5, 6), (7,8);"), "");
			assert_s(cl->execute("SELECT * FROM try WHERE age in (6,8) ORDER BY age ASC LIMIT 2;"),"");
			assert_s(cl->execute("SELECT * FROM try t WHERE t.age in (6,8) ORDER BY id DESC LIMIT 2;"),"");

			assert_s(cl->execute("CREATE TABLE bye (id integer);"),"failed");
			assert_s(cl->execute("INSERT INTO bye VALUES (3), (9), (10);"),"failed");
			assert_s(cl->execute("SELECT * FROM bye WHERE id <> 3;"),"failed");

			assert_s(cl->execute("SELECT COUNT(id) AS my_count FROM try;"),"failed");
			assert_s(cl->execute("SELECT COUNT(*) AS my_count  FROM try;"),"failed");
			assert_s(cl->execute("SELECT count(distinct age) AS hello from hi;"),"failed");

			assert_s(cl->execute("SELECT MAX(id) AS maximus, MIN(id) AS minimus FROM bye WHERE id > 3;"),"failed");

			assert_s(cl->execute("INSERT INTO bye VALUES (3), (7), (13), (43524)"),"failed");

			assert_s(cl->execute("SELECT id i FROM bye where id > 2 ORDER BY i ASC LIMIT 5; "),"failed");

			assert_s(cl->execute("SELECT id i FROM bye WHERE id in (7,13,3,4) AND (id in (7, 13)) ORDER BY i DESC LIMIT 9; "),"failed");

			assert_s(cl->execute("INSERT INTO bye (id) VALUES (4), (6), (-10)"),"failed");
			//assert_s(cl->execute(""),"failed");

			assert_s(cl->execute("DROP TABLE hi;"), "drop failed");
			assert_s(cl->execute("CREATE TABLE hi (id enc integer, name enc text);"), "failed");
			assert_s(cl->execute("INSERT INTO  hi VALUES (3, 'ra'), (4, 'c');"), "failed");

			assert_s(cl->execute("SELECT * FROM  hi ORDER BY id;"), "order by failed");

			cl->outputOnionState();*/
		} else {
			cl->execute(command);
		}
	}

	cl->exit();
	cout << "Goodbye!\n";

}

void microEvaluate(int argc, char ** argv) {
	cout << "\n\n Micro Eval \n------------------- \n \n";


	string masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);
	EDBClient * clsecure = new EDBClient("localhost", "raluca", "none", "cryptdb", masterKey);
	EDBClient * clplain = new EDBClient("localhost", "raluca", "none", "cryptdb");

	clsecure->VERBOSE = false;
	clplain->VERBOSE = false;

	clsecure->execute("CREATE TABLE tableeval (id integer, age integer);");
	clplain->execute("CREATE TABLE tableeval (id integer, age integer);");

	int nrInsertsSecure = 500;
	int nrInsertsPlain = 1000;
	int nrSelectsPlain = 2000;
	int nrSelectsSecure = 3000;

	int networkOverhead = 10; //10 ms latency per query

	startTimer();
	for (int i = 0; i < nrInsertsSecure; i++) {
		unsigned int val1 = rand() % 10;
		unsigned int val2 = rand() % 10;
		string qq = "INSERT INTO tableeval VALUES ( " + marshallVal(val1) + ", " + marshallVal(val2) + ");";
		clsecure->execute(getCStr(qq));
	}
	double endTimer = (readTimer()/(1.0 * nrInsertsSecure));
	printf("secure insertion: no network %6.6f ms with network %6.6f ms \n", endTimer, endTimer+networkOverhead);

	startTimer();
	for (int i = 0; i < nrInsertsPlain; i++) {
		unsigned int val1 = rand() % 10;
		unsigned int val2 = rand() % 10;
		string qq = "INSERT INTO tableeval VALUES ( " + marshallVal(val1) + ", " + marshallVal(val2) + ");";
		clplain->execute(getCStr(qq));
	}
	endTimer = (readTimer()/(1.0 * nrInsertsPlain));
	printf("plain insertion no network %6.6f ms with network %6.6f ms \n", endTimer, endTimer+networkOverhead);

	startTimer();
	for (int i = 0; i < nrSelectsSecure; i++) {
		unsigned int val1 = rand() % 50;
		string qq = "SELECT tableeval.id FROM tableeval WHERE tableeval.id = " + marshallVal(val1) + ";";
		clsecure->execute(getCStr(qq));
		//unsigned int val2 = rand() % 50;
		//qq = "SELECT tableeval.age FROM tableeval WHERE tableeval.age > " + marshallVal(val2) + ";";
		clsecure->execute(getCStr(qq));
	}
	endTimer = (readTimer()/(1.0 * nrSelectsSecure));
	printf("secure selection no network %6.6f ms with network %6.6f ms \n", endTimer, endTimer+networkOverhead);

	startTimer();
	for (int i = 0; i < nrSelectsPlain; i++) {
		unsigned int val1 = rand() % 50;
		string qq = "SELECT tableeval.id FROM tableeval WHERE tableeval.id = " + marshallVal(val1) + ";";
		clplain->execute(getCStr(qq));
		//unsigned int val2 = rand() % 50;
		//qq = "SELECT tableeval.age FROM tableeval WHERE tableeval.age > " + marshallVal(val2) + ";";
		clplain->execute(getCStr(qq));
	}
	endTimer = (readTimer()/(1.0 * nrSelectsPlain));
	printf("plain selection no network %6.6f ms with network %6.6f ms \n", endTimer, endTimer+networkOverhead);

	clsecure->execute("DROP TABLE tableeval;");
	clplain->execute("DROP TABLE tableeval;");

	clsecure->exit();
	clplain->exit();

}

//at this point this function is mostly to figure our how binary data works..later will become a test
/*
void tester::testMarshallBinary() {

    VERBOSE = true;

    execute("CREATE TABLE peoples (id bytea);");
    unsigned int len = 16;
    unsigned char * rBytes = randomBytes(len);
    cerr << " random Bytes are " << CryptoManager::marshallKey(rBytes) << " \n";
    cerr << " and marshalled they are " << marshallBinary(rBytes, len) << "\n";
    string query = "INSERT INTO peoples VALUES ( " + marshallBinary(rBytes, len) + " );";
    execute(getCStr(query));
    PGresult * res = execute("SELECT id, octet_length(id) FROM peoples;")->result;
    cout << "repr " << PQgetvalue(res, 0, 0) << "\n";
    execute("DROP TABLE peoples;");
}
 */

//integration test
void testEDBClient() {
	cout << "\n\n Integration Queries \n------------------- \n \n";

	string masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);
	EDBClient * cl = new EDBClient("localhost", "raluca", "none", "cryptdb", masterKey);
	cl->VERBOSE = true;

	cl->execute("CREATE TABLE people (id integer, name text, age integer);");

	cl->execute("INSERT INTO people VALUES (34, 'raluca', 100);");
	cl->execute("INSERT INTO people VALUES (35, 'alice', 20);");
	cl->execute("INSERT INTO people VALUES (36, 'bob', 10);");

	cl->execute("SELECT people.id, people.age, people.name FROM people;");
	cl->execute("SELECT people.name FROM people WHERE people.age > 20;");
	cl->execute("SELECT people.name, people.age FROM people WHERE people.name = 'alice' ;");

	cl->execute("DROP TABLE people;");

	cl->exit();

	cout << "\n------------------- \n Integration test succeeded \n\n";
}


void testCrypto() {
	cout << "TEST Crypto..\n";

	string masterKey = randomBytes(AES_KEY_BYTES);
	CryptoManager * cm = new CryptoManager(masterKey);

	AES_KEY * aeskey = cm->get_key_DET(masterKey);
	uint64_t plainVal = 345243;
	uint64_t ciph = cm->encrypt_DET(plainVal, aeskey);


	uint64_t decVal = cm->decrypt_DET(ciph, aeskey);

	cerr << "val " << plainVal << " enc " << ciph << " dec " << decVal << "\n";


	myassert(plainVal == decVal, "decryption of encryption does not match value \n");

	cout << "TEST Crypto succeeded \n";
}


void testPaillier() {
	int noTests = 100;
	int nrTestsEval = 100;

	string masterKey = randomBytes(AES_KEY_BYTES);
	CryptoManager * cm = new CryptoManager(masterKey);

	for (int i = 0 ; i < noTests ; i++) {
		int val = abs(rand() * 398493) % 12345;
		cerr << "Encrypt " << val << "\n";
		string ciph = cm->encrypt_Paillier(val);
		//myPrint(ciph, CryptoManager::Paillier_len_bytes);
		int dec = cm->decrypt_Paillier(ciph);
		//cerr << "\n decrypt to: " << dec << "\n";
		myassert(val == dec, "decrypted value is incorrect ");
	}

	string homCiph = homomorphicAdd(homomorphicAdd(cm->encrypt_Paillier(123), cm->encrypt_Paillier(234), cm->getPKInfo()),
			cm->encrypt_Paillier(1001), cm->getPKInfo());
	myassert(cm->decrypt_Paillier(homCiph) == 1358, "homomorphic property fails! \n");
	cerr << "decrypt of hom " <<  cm->decrypt_Paillier(homCiph)  << " success!! \n";

	cerr << "Test Paillier SUCCEEDED \n";

	cerr << "\n Benchmarking..\n";

	string ciphs[nrTestsEval];

	startTimer();
	for (int i = 0 ; i < noTests ; i++) {
		int val = (i+1) * 10;
		ciphs[i] = cm->encrypt_Paillier(val);
	}
	double res = readTimer();
	cerr << "encryption takes " << res/noTests << " ms  \n";


	startTimer();
	for (int i = 0 ; i < noTests ; i++) {
		int val = (i+1) * 10;

		int dec = cm->decrypt_Paillier(ciphs[i]);
		myassert(val == dec, "invalid decryption");
	}

	res = readTimer();
	cerr << "decryption takes " << res/noTests << " ms \n";
}

void testUtils() {
	const char * query = "SELECT sum(1), name, age, year FROM debug WHERE debug.name = 'raluca ?*; ada' AND a+b=5 ORDER BY name;";

	myPrint(parse(query, delimsStay, delimsGo, keepIntact));
}


void createTables(string file, EDBClient * cl) {
	ifstream createsFile(getCStr(file));

	if (createsFile.is_open()) {
		while (!createsFile.eof()) {

			string query = "";
			string line = "";
			while ((!createsFile.eof()) && (line.find(';') == string::npos)) {
				createsFile >> line;
				query = query + line;
			}
			if (line.length() > 0) {
				cerr << query << "\n";
				if (cl->execute(getCStr(query)) == NULL) {
					cerr << "FAILED on query " << query << "\n";
					createsFile.close();
					cl->exit();
					exit(1);
				}
			}

		}
	} else {
		cerr << "error opening file " + file + "\n";
	}

	createsFile.close();

}

void convertQueries() {

	ifstream firstfile("eval/tpcc/client.sql");
	ofstream secondfile("eval/tpcc/clientplain.sql");

	string line;

	int nr= 0;


	string transac = "";

	if (!firstfile.is_open()) {
		cerr << "cannot open input file \n";
		return;
	}

	if (!secondfile.is_open()) {
		cerr << "cannot open a second file \n";
		return;
	}

	while (! firstfile.eof() )
	{
		getline (firstfile,line);

		if (line.length() <= 1 ) {
			continue;
		}
		line = line + ";";

		//extract transaction number
		string no = line.substr(0, line.find('\t'));
		cerr << "no transac is " << no << "\n";
		line = line.substr(no.length()+1, line.length() - no.length()+1);

		if (no.compare(transac) != 0) {

			if (transac.length() > 0) {
				secondfile << "commit; \n" << "begin; \n";
			} else {
				secondfile << "begin; \n";
			}
			transac = no;
		}

		int index = 0;
		while (line.find(".", index) != string::npos) {
			int pos = line.find(".", index);
			index = pos+1;
			if (line[pos+1] >= '0' && line[pos+1] <= '9') {
				while ((line[pos]!=' ') && (line[pos] != ',') && (line[pos] != '\'')) {
					line[pos] = ' ';
					pos++;
				}
			}
		}

		while (line.find(">=") != string::npos) {
			int pos = line.find(">=");
			line[pos+1] = ' ';
			//TRACE SPECIFIC
			pos = pos + 3;
			int nr = 0;
			int oldpos = pos;
			while (line[pos] != ' ') {
				nr = nr * 10 + (line[pos]-'0');
				pos++;
			}
			nr = nr - 20;
			string replacement =  marshallVal((uint32_t)nr) + "     ";
			line.replace(oldpos, 9, replacement);

		}
		while (line.find("<=") != string::npos) {
			int pos = line.find("<");
			line[pos+1] = ' ';
		}
		while (line.find(" -") != string::npos) {
			int pos = line.find(" -");
			line[pos+1] = ' ';
		}
		secondfile << line  << "\n";
		nr ++;
	}

	cerr << "there are " << nr << " queries \n";
	firstfile.close();
	secondfile.close();

}



void test_train() {

	cerr << "training \n";
	string masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

	EDBClient * cl = new EDBClient("localhost", "raluca", "none", "cryptdb", masterKey);

	cl->VERBOSE = true;
	cl->dropOnExit = true;

	cl->train("eval/tpcc/sqlTableCreates");
	cl->train("eval/tpcc/querypatterns.txt");
	cl->train("eval/tpcc/index.sql");
	cl->train_finish();
	cl->create_trained_instance();

	cl->exit(true);

}

/*
void createIndexes(string indexF, EDBClient * cl) {
	ifstream tracefile(getCStr(indexF));

	string query;


	if (tracefile.is_open()) {
		while (!tracefile.eof()){

			getline(tracefile, query);
			if (query.length() > 1) {
				edb_result * res = cl->execute(getCStr(query));
				if (res == NULL) {
					cerr << "FAILED on query " << query << "\n";
					cl->exit();
					tracefile.close();
					exit(1);
				}
			}

		}
	}

	tracefile.close();
}

void convertDump() {

	ifstream fileIn("eval/tpcc/dumpcustomer.sql");
	ofstream fileOut("eval/tpcc/dumpcustomer");

	string query;

	int index = 0;
	if (fileIn.is_open()) {
			while (!fileIn.eof()){

				getline(fileIn, query);
				while (query.find("`")!=string::npos) {
					int pos = query.find("`");
					query[pos] = ' ';
				}
				if (query.length() > 1) {
					fileOut << query << "\n";
					index++;
				}

			}


    }

	cerr << "there are " << index << "entries \n";
	fileIn.close();
	fileOut.close();

}

 */

/*
const string createFile = "eval/tpcc/sqlTableCreates";
const string queryTrainFile = "eval/tpcc/querypatterns.txt";
const string dumpFile = "eval/tpcc/pieces/dump";
const string queryFilePrefix = "eval/tpcc/";
const string indexFile = "eval/tpcc/index.sql";
const int nrDataToLoad = 100000; //how much the threads load in total
const bool verbose = true;
const bool isSecureLoad = true;
const int logFrequency = 500;



void runTrace(const char * suffix, int nrQueriesToRun, int isSecure) {

	struct timeval tvstart, tvend;

	unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);
	EDBClient * cl;

	if (isSecure) {
		cl = new EDBClient("cryptdb", masterKey);
	} else {
		cl = new EDBClient("cryptdb");
	}
	cl->VERBOSE = verbose;

	cerr << "prepare \n";
	cl->nosubmit = true;
	createTables(createFile, cl);
	runForSteps(queryTrainFile, 100, cl);
	createIndexes(indexFile, cl);
	cl->nosubmit = false;

	gettimeofday(&tvstart, NULL);

	runForSteps(queryFilePrefix+suffix, nrQueriesToRun, cl);

	gettimeofday(&tvend,NULL);
	cerr << "all trace took " << ((tvend.tv_sec - tvstart.tv_sec)*1.0 + (tvend.tv_usec - tvstart.tv_usec)/1000000.0) << "s \n";


}

 */

string suffix(int no) {
	int fi = 97 + (no/26);
	int se = 97 + (no%26);
	string first = string("") + (char)fi;
	string second = string("") + (char)se;
	string res = first + second;

	return res;
}
/*
void tester::loadData(EDBClient * cl, string workload, int logFreq) {

	ifstream dataFile(getCStr(workload));
	ofstream outFile(getCStr(workload+"answer"));

	if ((!dataFile.is_open()) || (!outFile.is_open())) {
		cerr << "could not open file " << workload << "or the answer file " << " \n";
		exit(1);
	}

	string query;

	int index = 0;
	while (!dataFile.eof()) {

		getline(dataFile, query);

		if (query.length() > 0) {
			if (index % logFreq == 0) {
				cerr << "load entry " << index << " from " << workload << "\n" ;// query " << query << "\n";
			}
 */
/*edb_result * res = cl->execute(getCStr(query));
			if (index % logFreq== 0) {//cout << "executed\n";
			}
			if (res == NULL) {
				cerr << workload + "offensive insert query " << query << "  \n";
				while (res == NULL) {
					cerr << "retrying \n";
					sleep(10);
					res = cl->execute(getCStr(query));
				//cl->exit();
				//dataFile.close();
				//exit(1);
				}
			}*//*
			list<const char *> ress;
			try {
				ress = tcl->rewriteEncryptQuery(getCStr(query));
			} catch (SyntaxError se) {
				cerr << "syntax error " << se.msg << "\n";
				exit(1);
			}
			outFile << ress.front() << "\n";

		}

		index++;
	}

	outFile.close();
	dataFile.close();

	return;
}



bool isbegin(string s) {
	if (s.compare("begin;") == 0){
		return true;
	}
	if (s.compare("begin; ") == 0){
			return true;
	}
	return false;
}
bool iscommit(string s) {
	if (s.compare("commit;") == 0){
		return true;
	}
	if (s.compare("commit; ") == 0){
			return true;
	}
	return false;
}

void runTrace(EDBClient * cl, int logFreq, string workload, bool isSecure, bool hasTransac,
		int & okinstrCount, int & oktranCount, int & totalInstr, int & totalTran) {

	ifstream tracefile(getCStr(workload));

	string query;

	if (!tracefile.is_open()) {
		cerr << "cannot open " << workload << "\n";
	}

	int count = 0;//nr of failed instructions

	int index = 0; //the number of query execute currently
	//counts for the number of instructions or transactions succesfully run
	okinstrCount = 0;
    oktranCount = 0;
    totalTran = 0;
    totalInstr = 0;

    bool tranAborted = false;

    while (!tracefile.eof()) {


		getline(tracefile, query);

		if (query.length() < 1) {
			continue;
		}

		index++;
		if (index % logFreq	 == 0) {cerr << workload << " " << index << "\n";}

		if (!hasTransac) {
			if (isSecure) {
				edb_result * res = cl->execute(getCStr(query));
				if (res == NULL) {
					count++;
				}
			} else {
				PGresult * res = cl->plain_execute(getCStr(query));
				if (!((PQresultStatus(res) == PGRES_TUPLES_OK) || (PQresultStatus(res) == PGRES_COMMAND_OK))) {
					count++;
				}
			}
		} else {

				if (isbegin(query)) {
					tranAborted = false;
					totalTran++;
				}
				if (tranAborted) {
						continue;
				}

				bool instrOK = true;
				if (isSecure) {
					edb_result * res = cl->execute(getCStr(query));
					if (res == NULL) {
						instrOK = false;
					}
				} else {
					PGresult * res = cl->plain_execute(getCStr(query));
					if (!((PQresultStatus(res) == PGRES_TUPLES_OK) || (PQresultStatus(res) == PGRES_COMMAND_OK))) {
						instrOK = false;
					}
				}

				if (!instrOK) {
					PGresult * res = cl->plain_execute("abort;");
					if (!((PQresultStatus(res) == PGRES_TUPLES_OK) || (PQresultStatus(res) == PGRES_COMMAND_OK))) {
								cerr << workload << ": returning bad status even on abort, exiting ;";
								tracefile.close();
								exit(1);
					}
					tranAborted = true;
					cerr << "aborting curr tran \n";
				} else {
					if (iscommit(query)) {
						oktranCount++;
						//cerr << "oktranCount becomes " << oktranCount << " \n";
					}

				    okinstrCount++;

				}
		}



	}

	totalInstr = index;
	tracefile.close();



	return;
}


void simpleThroughput(int noWorkers, int noRepeats, int logFreq, int totalLines, string dfile, bool isSecure, bool hasTransac) {
	cerr << "throughput benchmark \n";
			 */
//	int res = system("rm eval/pieces/*");
/*
	ifstream infile(getCStr(dfile));

	int linesPerWorker = totalLines / noWorkers;

	string query;

	if (!infile.is_open()) {
		cerr << "cannot open " + dfile << "\n";
		exit(1);
	}

	//prepare files
	for (int i = 0; i < noWorkers; i++) {
		string workload = string("eval/pieces/piece") + suffix(i);
		ofstream outfile(getCStr(workload));

		if (!outfile.is_open()) {
			cerr << "cannot open file " << workload << "\n";
			infile.close();
			exit(1);
		}

		getline(infile, query);

		if (hasTransac && (!isbegin(query))) {
			outfile << "begin; \n";
		}

		for (int j = 0; j < linesPerWorker; j++) {
			outfile << query << "\n";
			if (j < linesPerWorker-1) {getline(infile, query);}
		}

		if (hasTransac && (!iscommit(query))) {
			outfile << "commit; \n";
		}

		outfile.close();

		//we need to concatenate the outfile with itself noRepeats times
		res = system("touch temp;");
		for (int j = 0; j < noRepeats; j++) {
			res = system(getCStr(string("cat temp ") + workload + string(" > temp2;")));
			res = system("mv temp2 temp");
		}
		res = system(getCStr(string("mv temp " + workload)));

	}

	infile.close();

    res = system("rm eval/pieces/result;");
    res = system("touch eval/pieces/result;");

    ofstream resultFile("eval/pieces/result");
    ifstream resultFileIn;

    if (!resultFile.is_open()) {
    	cerr << "cannot open result file \n";
    	exit(1);
    }

	timeval starttime, endtime;

	int childstatus;
    int index;
    int i;
    pid_t pids[noWorkers];

	double interval, querytput, querylat, trantput, tranlat;
	int allInstr, allInstrOK, allTran, allTranOK;

	for (i = 0; i < noWorkers; i++) {
		index = i;
		pid_t pid = fork();
		if (pid == 0) {
			goto dowork;
		} else if (pid < 0) {
			cerr << "failed to fork \n";
			exit(1);
		} else { // in parent
			pids[i] = pid;
		}
	}

	//parent
	for (i = 0; i < noWorkers; i++) {

		if (waitpid(pids[i], &childstatus, 0) == -1) {
			cerr << "there were problems with process " << pids[i] << "\n";
		}

	}

	resultFile.close();

	resultFileIn.open("eval/pieces/result", ifstream::in);

	if (!resultFileIn.is_open()) {
		cerr << "cannot open results file to read\n";
		exit(1);
	}

	querytput = 0; querylat = 0; trantput = 0; tranlat = 0;
	allInstr = 0; allInstrOK = 0; allTran = 0; allTranOK = 0;

	for (i = 0; i < noWorkers; i++) {

		double currquerytput, currquerylat, currtrantput, currtranlat;
		int currtotalInstr, currokInstr, currtotalTran, currokTran;

		if (!hasTransac) {
			resultFileIn >> index; resultFileIn >> interval; resultFileIn >> currquerytput; resultFileIn >> currquerylat;
			cerr << index << " " << interval << " sec " << currquerytput << " queries/sec " << currquerylat << " secs/query \n";
			querytput = querytput + currquerytput;
			querylat = querylat + currquerylat; }
		else {
			resultFileIn >> index;
			resultFileIn >> interval; resultFileIn >>  currtrantput; resultFileIn >> currquerytput; resultFileIn >> currtranlat; resultFileIn >> currquerylat; resultFileIn >> currtotalInstr; resultFileIn >> currokInstr; resultFileIn >> currtotalTran; resultFileIn >> currokTran;
			querytput +=currquerytput;
			querylat +=currquerylat;
			trantput += currtrantput;
			tranlat += currtranlat;
			allInstr += currtotalInstr;
			allInstrOK += currokInstr;
			allTran += currtotalTran;
			allTranOK += currokTran;

			cerr << "worker " << i << " interval " << interval << " okInstr " <<  currokInstr << " okTranCount " << currokTran << " totalInstr " << currtotalInstr << " totalTran " <<  currtotalTran << "\n";

		}
	}

	if (!hasTransac) {
		cerr <<"overall:  throughput " << querytput << " queries/sec latency " << querylat/noWorkers << " sec/query \n";
	} else {
		querylat = querylat / noWorkers;
		tranlat  = tranlat / noWorkers;
		if (isSecure) {
			cerr << "secure: ";
		} else {
			cerr << "plain: ";
		}
		cerr << " querytput " << querytput << " querylat " << querylat << " trantput " << trantput << " tranlat " << tranlat << " allInstr " << allInstr << " allInstrOK " << allInstrOK << " tran failed" << allTran-allTranOK << " allTransacOK " << allTranOK << " \n";


	}
	resultFileIn.close();

	return;


	//children:
	dowork:

	EDBClient * cl;

	if (isSecure) {
		unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

    	cl = new EDBClient("cryptdb", masterKey);

		cl->train("schema");
		cl->train("queries");
		cl->train_finish();


	} else {
		 cl = new EDBClient("cryptdb");
	}

	string workload = string("eval/pieces/piece") + suffix(index);
	//execute on the workload
	cerr << "in child workload file <" << workload << "> \n";
	cerr << "value of index is " << index << "\n";

	int okInstrCount, okTranCount, totalInstr, totalTran;


	gettimeofday(&starttime, NULL);

	runTrace(cl, logFreq, workload, isSecure, hasTransac, okInstrCount, okTranCount, totalInstr, totalTran);
	//now we need to start the workers
	gettimeofday(&endtime, NULL);


	interval = 1.0 * timeInSec(starttime, endtime);

	if (!hasTransac) {
		querytput = linesPerWorker *  noRepeats * 1.0 / interval;
		querylat = interval / (linesPerWorker * noRepeats);

		resultFile << index << " " << interval << " " << querytput << " " << querylat << "\n";
	} else { //report  workerid  timeinterval  trantput querytput tranlate querylate totalInstr okInstr totalTRan okTran
		myassert(noRepeats == 1, "repeats more than one,transactions fail automatically\n");
		double trantput = okTranCount * 1.0 / interval;
		double querytput = okInstrCount*1.0/interval;
		double tranlat = interval*1.0/okTranCount;
		double querylat = interval*1.0/okInstrCount;
		resultFile << index << " " << interval << " " << trantput << " " << querytput << " " << tranlat << " " << querylat << " " << totalInstr << " " << okInstrCount << " " << totalTran << " " << okTranCount << "\n";
	}

    cl->exit();

	return;
}

void createInstance() {
	unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

	EDBClient * cl = new EDBClient("cryptdb", masterKey);

	cl->train("eval/tpcc/sqlTableCreates");
	cl->train("eval/tpcc/querypatterns.txt");
	cl->train("eval/tpcc/index.sql");
	cl->train_finish();

	cl->create_trained_instance(true);

	EDBClient * plaincl = new EDBClient("cryptdb");

	int res = system("psql < eval/tpcc/sqlTableCreates");
	res = system("psql < eval/tpcc/index.sql");

	cl->exit(false);
	plaincl->exit(false);

}

void parallelLoad(int noWorkers, int totalLines, int logFreq,  string dfile, int workeri1, int workeri2) {


	cerr << "Parallel loading from " << dfile << ". \n";

	unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

	tester t = tester("cryptdb", masterKey);

	int res = system("mkdir eval/pieces;");
 */
//	res = system("rm eval/pieces/*");
/*
	string splitComm = "split  -l " + marshallVal((uint32_t)(totalLines/noWorkers)) + " -a 2 " + dfile + " eval/pieces/piece";
	cerr << "split comm " << splitComm << "\n";
	res  = system(getCStr(splitComm));
	myassert(res == 0, "split failed");

	EDBClient * cl = new EDBClient("cryptdb", masterKey);

	cl->train("eval/tpcc/sqlTableCreates");
	cl->train("eval/tpcc/querypatterns.txt");
	cl->train("eval/tpcc/index.sql");
	cl->train_finish();


	cl->create_trained_instance(false);

	int index = 0;
	for (int i = workeri1; i <= workeri2; i++) {
		index = i;
		pid_t pid = fork();
		if (pid == 0) {
			goto dowork;
		} else if (pid < 0) {
			cerr << "failed to fork \n";
			exit(1);
		}
	}

	//parent
	return;

	dowork:
	string workload = string("eval/pieces/piece") + suffix(index);
	//execute on the workload
	cerr << "in child workload file <" << workload << "> \n";
	cerr << "value of index is " << index << "\n";
	t.loadData(cl, workload, logFreq);
}


void executeQueries(EDBClient * cl, string workload, string resultFile, int timeInSecs, int logFreq) {
	ifstream tracefile(getCStr(workload));
	string query;
	struct timeval tvstart, tvend;

	if (!tracefile.is_open()) {
		cerr << "cannot open " << workload << "\n";
		exit(1);
	}

	gettimeofday(&tvstart, NULL);
	gettimeofday(&tvend,NULL);

	int index = 0;

	while (timeInSec(tvstart, tvend) < timeInSecs) {
		while (!tracefile.eof()) {
			getline(tracefile, query);
			edb_result * res = cl->execute(getCStr(query));
			index++;
			if (index % logFreq == 0) {cerr << index << "\n";}
			if (res == NULL) {
				cerr << "FAILED on query " << query << "\n";
				cerr << "query no " << index << "\n";
				cl->exit();
				tracefile.close();
				exit(1);
			}
			if (index % 100 == 0) {
				gettimeofday(&tvend, NULL);
				if (timeInSec(tvstart, tvend) >= timeInSecs) {
					goto wrapup;
				}
			}

		}

		gettimeofday(&tvend,NULL);
	}

	wrapup:
	tracefile.close();
	ofstream resFile(getCStr(resultFile));
	if (!resFile.is_open()) {
		cerr << "cannot open result file " << resultFile << "\n";
		exit(-1);
	}
	resFile << index << "\n";
	resFile << timeInSec(tvstart, tvend) << "\n";
	resFile.close();
}


void throughput(int noClients, int totalLines, int timeInSecs, int logFreq, string queryFile, bool isSecure) {
	//prepare files

	int res = system("mkdir eval/queries;");
 */
//	res = system("rm eval/queries/*");
/*
	string splitComm = "split  -l " + marshallVal((uint32_t)(totalLines/noClients)) + " -a 1 " + queryFile + " eval/queries/piece";
	cerr << "split comm " << splitComm << "\n";
	res  = system(getCStr(splitComm));
	myassert(res == 0, "split failed");

	EDBClient * cl;

	if (isSecure) {

		unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

		cl = new EDBClient("cryptdb", masterKey);

		cl->train("eval/tpcc/sqlTableCreates");
		cl->train("eval/tpcc/querypatterns.txt");
		cl->train("eval/tpcc/index.sql");
		cl->train_finish();

	}
	else {
		cl = new EDBClient("cryptdb");
	}

	int index = 0;
	pid_t pids[noClients];
	string resultFile[noClients];
	int i, childstatus;
	pid_t pid;
	double throughput;

	for (i = 0; i < noClients; i++) {
		resultFile[i] = "eval/queries/answer" + (char)('a'+i);
		index = i;
		pid = fork();
		if (pid == 0) {
			goto dowork;
		} else if (pid < 0) {
			cerr << "failed to fork \n";
			exit(1);
		} else {
			//parent
			pids[i] = pid;
		}
	}


	//parents
	for (i = 0; i < noClients; i++) {

		if (waitpid(pids[i], &childstatus, 0) == -1) {
			cerr << "there were problems with process " << pids[i] << "\n";
		}
	}

	//collect results and compute throughput
	throughput = 0;
	for (int i = 0; i < noClients; i++) {
		string resfile = string("eval/queries/answer")+char('a'+i);
		ifstream result(getCStr(resfile));
		int count;
		double secs;
		result >> count;
		result >> secs;
		cerr << "worker i processed " << count << " in " << secs << " secs \n";
		throughput += (count*1.0/secs);
	}

	cerr << "overall throughput " << throughput << "\n";

	return;

	dowork: //child
	string workload = string("eval/queries/piece") + (char)('a' + index);
	//execute on the workload
	cerr << "in child workload file <" << workload << "> \n";
	cerr << "value of index is " << index << "\n";
	executeQueries(cl, workload, resultFile[index], timeInSecs, logFreq);


	return;



}

void parse() {
	ifstream f("queries");
	ofstream o("queries2");
	string q;

	while (!f.eof()) {
		getline(f, q);

		if (q.length() > 0) {
			o << q << ";\n";
		}
	}

	f.close();
	o.close();
}

void simple() {

	unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

	EDBClient * cl = new EDBClient("cryptdb", masterKey);

	cl->train("schema");
	cerr << "done with creates \n";

	cl->train("queries");
	cl->train_finish();

//	cl->create_trained_instance();

	ifstream f("insertslast");

	if (!f.is_open()) {
		cerr << "cannot open f \n";
		exit(1);
	}

	cl->ALLOW_FAILURES = true;

	int log = 2000;
	int index = 0;
	string q;
	while (!f.eof()) {
		getline(f, q);
		index++;
		if (index % log == 0) {cerr << index << "\n";}
		if (q.length() == 0) {
			continue;
		}


		cl->execute(getCStr(q));
	}

	cerr << "done \n";
	return;


}

void latency(string queryFile, int maxQueries, int logFreq, bool isSecure, int isVerbose) {
 */
/*ofstream outputnew("cleanquery"); //DO

	if (!outputnew.is_open()) { //DO
		cerr << "cannot open cleanquery file \n";
		exit(1);
	}
 */
/*	cerr << "starting \n";
	struct timeval tvstart;
	struct timeval tvend;

	EDBClient * cl;

	if (isSecure) {

		unsigned char * masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);

		cl = new EDBClient("cryptdb", masterKey);

		if (isVerbose) {
				cl->VERBOSE = true;
		} else {
				cl->VERBOSE = false;
		}


		cl->train("eval/tpcc/sqlTableCreates");
		cerr << "done with creates \n";

		cl->train("eval/tpcc/querypatterns.txt");


		cl->train_finish();

		cerr << "done \n";
		return;

	}
	else {
		cl = new EDBClient("cryptdb");


	}

	if (isVerbose) {
		cl->VERBOSE = true;
	} else {
		cl->VERBOSE = false;
	}

	ifstream tracefile(getCStr(queryFile));

	if (!tracefile.is_open()) {
		cerr << "cannot open file " << queryFile << "\n";
		exit(-1);
	}

	gettimeofday(&tvstart, NULL);

	string query;

	int index = 0;
	while (!tracefile.eof()) {
		getline(tracefile, query);
		if (query.size() == 0) {
			continue;
		}
 */	/*	try {
			PGresult * res = cl->plain_execute(getCStr(query));//DO
			ExecStatusType est = PQresultStatus(res);
			if ((est == PGRES_COMMAND_OK) || (est == PGRES_TUPLES_OK)) {
			  outputnew << query << "\n";
			} else {
				cl->plain_execute("abort;");
			}
  */
/*			cl->rewriteEncryptQuery(getCStr(query));

			//cerr << query << "\n";
			//cerr << resQuery.front() << "\n";
		}  catch (SyntaxError se) {
			cerr << se.msg << "\n aborting \n";
			return;
		}

		if (index % logFreq == 0) {cerr << index << "\n";}

		index++;
		if (index == maxQueries) {
			break;
		}

	}

	//outputnew.close(); //DO

	gettimeofday(&tvend,NULL);
	tracefile.close();

	cerr << "file " << queryFile << " overall took " << timeInSec(tvstart, tvend) << " each statement took " << (timeInSec(tvstart, tvend)/index*1.0)*1000.0  << " ms \n";

}
 */

void encryptionTablesTest() {
	EDBClient * cl = new EDBClient("localhost", "raluca", "none", "cryptdb", randomBytes(AES_KEY_BYTES));

	int noHOM = 100;
	int noOPE = 100;

	cl->VERBOSE = true;

	if (cl->execute("CREATE TABLE try (age integer);") == NULL) {return;};

	struct timeval starttime, endtime;

	gettimeofday(&starttime, NULL);
	cl->createEncryptionTables(noHOM, noOPE);
	gettimeofday(&endtime, NULL);

	cerr << "time per op" << timeInSec(starttime, endtime)*1000.0/(noHOM+noOPE) << "\n";

	if (cl->execute("INSERT INTO try VALUES (4);")  == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (5);") == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (5);") == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (5);") == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (5);") == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (5);") == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (5);") == NULL) {return;};
	if (cl->execute("INSERT INTO try VALUES (10000001);") == NULL) {return;};
	if (cl->execute("SELECT age FROM try WHERE age > 1000000;") == NULL) {return;};
	if (cl->execute("DROP TABLE try;") == NULL) {return;};
	cl->exit();
}

void testParseAccess() {

	EDBClient * cl = new EDBClient("localhost", "raluca", "none", "raluca", BytesFromInt(mkey, AES_KEY_BYTES));

	cl->VERBOSE = true;
	cl->execute("CREATE TABLE test (gid integer, t text encfor gid, f integer encfor mid, mid integer);");

	string q = "INSERT INTO test VALUES (3, 'ra', 5, 4);";
	cerr << q;
	list<string> query = parse(getCStr(q), delimsStay, delimsGo, keepIntact);

	TMKM tmkm;
	QueryMeta qm;

	assert_s(false, "test no longer valid because of interface change ");

	//cl->getEncForFromFilter(INSERT, query, tmkm, qm); <-- no longer valid


	map<string, string>::iterator it = tmkm.encForVal.begin();


	while (it != tmkm.encForVal.end()) {
		cout << it->first << " " << it->second << "\n";
		it++;
	}

	q = "SELECT * FROM test WHERE gid = 3 AND mid > 4 AND t = 'ra';";
	cerr << q;
	query = parse(getCStr(q), delimsStay, delimsGo, keepIntact);

	//cl->getEncForFromFilter(SELECT, query, tmkm, qm); <-- no longer valid due to interface change

	it = tmkm.encForVal.begin();


	while (it != tmkm.encForVal.end()) {
		cout << it->first << " " << it->second << "\n";
		it++;
	}
	cl->execute("DROP TABLE test;");

}


void autoIncTest() {

	string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
	string host = "localhost";
	string user = "root";
	string db = "mysql";
	string pwd = "letmein";
	cerr << "connecting to host " << host << " user " << user << " pwd " << pwd << " db " << db << endl;
	EDBClient * cl = new EDBClient(host, user, pwd, db, masterKey);
	cl->VERBOSE = true;

	cl->plain_execute("DROP TABLE IF EXISTS t1, users;");
	assert_s(cl->execute("CREATE TABLE t1 (id integer, post encfor id det text, age encfor id ope bigint);"), "failed");
	assert_s(cl->execute("CREATE TABLE users (id equals t1.id integer, username givespsswd id text);"), "failed");
	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('alice', 'secretalice');"), "failed to log in user");
	assert_s(cl->execute("DELETE FROM "psswdtable" WHERE username = 'al\\'ice';"), "failed to logout user");
	assert_s(cl->execute("INSERT INTO "psswdtable" VALUES ('alice', 'secretalice');"), "failed to log in user");
	assert_s(cl->execute("INSERT INTO users VALUES (1, 'alice');"), "failed to add alice in users table");
	ResType * rt = cl->execute("INSERT INTO t1 (post, age) VALUES ('A you go', 23);");
	assert_s(rt->at(0).at(0).compare("cryptdb_autoinc") == 0, "fieldname is not autoinc");

	assert_s(rt->at(1).at(0).compare("1") == 0, "autoinc not correct1");

	rt = cl->execute("INSERT INTO t1 (post, age) VALUES ('B there you go', 23);");
	assert_s(rt->at(1).at(0).compare("2") == 0, "autoinc not correct2");

	rt = cl->execute("INSERT INTO t1 VALUES (3, 'C there you go', 23);");
	cerr << "result is  " << rt->at(1).at(0) << "\n";
	assert_s(rt->at(1).at(0).compare("3") == 0, "autoinc not correct3");

	rt = cl->execute("INSERT INTO t1 (post, age) VALUES ( 'D there you go', 23);");
	assert_s(rt->at(1).at(0).compare("4") == 0, "autoinc not correct4");

	//cl->~EDBClient();
}

void accessManagerTest() {

	cerr << "============================= Equation ========================" << endl;

	Equation eq;
	string test = "1+2";
	eq.set(test);
	string res1 = eq.rpn();
	test = "1+(1*1+1)";
	eq.set(test);
	string res2 = eq.rpn();
	assert_s(res1.compare(res2) == 0, "1+2="+res1+" != 1+(1*1+1)="+res2+";  this is sad");

	test = "1";
	eq.set(test);
	res1 = eq.rpn();
	assert_s(res1.compare("1") == 0, "1 != 1");

	test = "10/5+6";
	eq.set(test);
	res1 = eq.rpn();
	test = "(2*4)/1+(3-5)+2";
	eq.set(test);
	res2 = eq.rpn();
	assert_s(res1.compare(res2) == 0, "1+2="+res1+" != 1+(1*1+1)="+res2+";  this is sad");

	test = "(5.5+.5)*2";
	eq.set(test);
	res1 = eq.rpn();
	test = "(12-.3)+.2+.1";
	eq.set(test);
	res2 = eq.rpn();
	assert_s(res1.compare(res2) == 0, "1+2="+res1+" != 1+(1*1+1)="+res2+";  this is sad");


	/*cerr << "============================= Consolidate ========================" << endl;
	assert_s(isOnly("10",math,noMath), "10 is apparently not math");
	assert_s(isOnly("8-3",math,noMath), "8-3 is apparently not math");
	assert_s(isOnly("(1+2)/3*4.5-7",math,noMath), "longer equation is not math");

	string basic[] = {"WHERE","a", "=","8-3","AND","b","=","10","+","2","AND","c=","a+2","AND","x=3+6"};
	string basic_r[] = {"WHERE","a", "=","5","AND","b","=","12","AND","c=","a+2","AND","x=3+6"};
	list<string> word_list (basic, basic + sizeof(basic)/sizeof(int));
	list<string> word_res (basic_r, basic_r + sizeof(basic_r)/sizeof(int));
	string select[] = {"SELECT", "post", "FROM", "t1", "WHERE", "id", "=", "1", "AND", "age", "=", "23"};
	list<string> select_list(select, select + sizeof(select)/sizeof(int));
	list<string> select_res(select, select + sizeof(select)/sizeof(int));
	string limit[] = {"SELECT", "post", "FROM", "t1", "WHERE", "id", "=", "1", "AND", "age", "=", "23", "LIMIT", "5"};
	list<string> limit_list(limit, limit + sizeof(limit)/sizeof(int));
	list<string> limit_res(limit, limit + sizeof(limit)/sizeof(int));
	string insert2[] = {"INSERT", "INTO", "t1", "VALUES", "(", "3+5", ",", "23", ",", "43-34",")"};
	string insert_r[] = {"INSERT", "INTO", "t1", "VALUES", "(", "8", ",", "23", ",", "9",")"};
	list<string> insert_list(insert2, insert2 + sizeof(insert2)/sizeof(int));
	list<string> insert_res(insert_r, insert_r + sizeof(insert_r)/sizeof(int));
	string update[] = {"UPDATE", "t1", "WHERE", "field2", "=", "'", "14", "'", "SET", "a=a", "+", "9", "-8"};
	string update_r[] = {"UPDATE", "t1", "WHERE", "field2", "=", "'", "14", "'", "SET", "a=a", "+", "1"};
	list<string> update_list(update, update + sizeof(update)/sizeof(int));
	list<string> update_res(update_r, update_r + sizeof(update_r)/sizeof(int));

	vector<list<string> > input;
	input.push_back(word_list);
	input.push_back(select_list);
	input.push_back(limit_list);
	input.push_back(insert_list);
	input.push_back(update_list);
	vector<list<string> > res;
	res.push_back(word_list);
	res.push_back(select_list);
	res.push_back(limit_list);
	res.push_back(insert_list);
	res.push_back(update_list);

	vector<list<string> >::iterator inp = input.begin();
	vector<list<string> >::iterator re = res.begin();
	list<string>::iterator in;
	list<string>::iterator r;
	for(inp = input.begin(); inp != input.end(); inp++, re++) {
		consolidate(*inp);
		assert_s(inp->size() == re->size(), "result and expected results are different sizes");
		in = inp->begin();
		r = re->begin();
		for(in = inp->begin(); in != inp->end(); in++, r++) {
			assert_s(in->compare(*r) == 0, "result and expected results disagree");
		}
	}

	return;*/

	//Testing new AccessManager, called AccessManager2
	cerr << "============================= AccessManager2 ==================================" << endl;
	MetaAccess * meta;
	meta = new MetaAccess(new Connect("localhost", "root", "letmein", "mysql"),true);

	meta->addEquals("u.uid","g.uid");
	meta->addAccess("u.uid","g.gid");

	assert_s(!meta->CheckAccess(), "passes access check with no givesPsswd");

	meta->addGives("u.uname");

	assert_s(!meta->CheckAccess(), "passes access check with broken access tree");

	KeyAccess * am;
	am = new KeyAccess(new Connect("localhost","root","letmein","mysql"));

	am->addEquals("u.uid","g.uid"); //1
	am->addAccess("u.uname","u.uid");
	am->addEquals("m.uid","u.uid"); //3
	am->addAccess("m.uid","m.mess");
	am->addAccess("u.uid","u.acc");
	am->addAccess("g.uid","g.gid");
	am->addEquals("g.gid","x.gid"); //2
	am->addAccess("f.gid","f.fid");
	am->addAccess("x.gid","x.mailing_list");
	am->addEquals("g.gid","f.gid"); //4
	am->addAccess("m.mess","m.sub");
	am->addAccess("f.gid","u.acc");

	am->addGives("u.uname");



	am->addAccess("msgs.msgid", "msgs.msgtext");

	am->addEquals("msgs.msgid","privmsgs.msgid");
	am->addEquals("privmsgs.recid", "users.userid");	

	am->addAccess("privmsgs.recid", "privmsgs.msgid");
	am->addAccess("privmsgs.senderid", "privmsgs.msgid");

	am->addEquals("users.userid", "privmsgs.senderid");

	am->addGives("users.username");
	am->addAccess("users.username", "users.userid");


	cerr << "\n";

	std::set<string> generic_gid = am->getEquals("g.gid");
	assert_s(generic_gid.find("f.gid") != generic_gid.end(), "f.gid is not equal to g.gid");
	assert_s(generic_gid.find("x.gid") != generic_gid.end(), "x.gid is not equal to g.gid");

	std::set<string> generic_uid = am->getEquals("m.uid");
	assert_s(generic_uid.find("u.uid") != generic_uid.end(), "u.uid is not equal to m.uid");
	assert_s(generic_uid.find("g.uid") != generic_uid.end(), "g.uid is not equal to m.uid");
	assert_s(generic_uid.find("f.gid") == generic_uid.end(), "m.uid is equal to f.gid");

	std::set<string> gid_hasAccessTo = am->getTypesHasAccessTo("g.gid");
	assert_s(gid_hasAccessTo.find("f.fid") != gid_hasAccessTo.end(), "g.gid does not have access to f.fid");
	assert_s(gid_hasAccessTo.find("x.mailing_list") != gid_hasAccessTo.end(), "g.gid does not have access to x.mailing_list");
	assert_s(gid_hasAccessTo.find("g.uid") == gid_hasAccessTo.end(), "g.gid does have access to g.uid");
	assert_s(gid_hasAccessTo.find("f.gid") == gid_hasAccessTo.end(), "getTypesHasAccessTo(g.gid) includes f.gid");
	assert_s(gid_hasAccessTo.find("g.gid") == gid_hasAccessTo.end(), "getTypesHasAccessTo(g.gid) includes g.gid");

	std::set<string> mess_accessibleFrom = am->getTypesAccessibleFrom("m.mess");
	assert_s(mess_accessibleFrom.find("m.uid") != mess_accessibleFrom.end(), "m.mess is not accessible from m.uid");
	assert_s(mess_accessibleFrom.find("u.uid") != mess_accessibleFrom.end(), "m.mess is not accessible from u.uid");
	assert_s(mess_accessibleFrom.find("g.uid") != mess_accessibleFrom.end(), "m.mess is not accessible from g.uid");
	assert_s(mess_accessibleFrom.find("g.gid") == mess_accessibleFrom.end(), "m.mess is accessible from g.gid");
	assert_s(mess_accessibleFrom.find("u.uname") == mess_accessibleFrom.end(), "m.mess is accessible from u.uname in one link");

	std::set<string> acc_accessibleFrom = am->getGenAccessibleFrom(am->getGeneric("u.acc"));
	assert_s(acc_accessibleFrom.find(am->getGeneric("u.uid")) != acc_accessibleFrom.end(), "gen acc is not accessible from gen uid");
	assert_s(acc_accessibleFrom.find(am->getGeneric("g.gid")) != acc_accessibleFrom.end(), "gen acc is not accessible from gen gid");
	assert_s(acc_accessibleFrom.find(am->getGeneric("f.fid")) == acc_accessibleFrom.end(), "gen acc is accessible from gen fid");


	int create = am->CreateTables();
	create += am->DeleteTables();
	create += am->CreateTables();

	assert_s(create >= 0, "create/delete/create tables failed");

	cerr << "BFS, DFS tests \n";


	Prin alice;
	alice.type = "u.uname";
	alice.value = "alice";

	list<string> bfs = am->BFS_hasAccess(alice);
	list<string>::iterator it;
	cerr << endl;
	for(it = bfs.begin(); it != bfs.end(); it++) {
		cerr << *it << ", ";
	}
	cerr << "\n" << endl;

	list<string> dfs = am->DFS_hasAccess(alice);
	assert_s(bfs.size() == dfs.size(), "bfs and dfs have different sizes");
	for(it = dfs.begin(); it != dfs.end(); it++) {
		cerr << *it << ", ";
	}
	cerr << endl;


	cerr << "=============================================" << endl;
	cerr << "raluca tests" << endl;

	Prin name_a;
	name_a.type = "users.username";
	name_a.value = "alice";
	Prin name_b;
	name_b.type = "users.username";
	name_b.value = "bob";
	Prin user1;
	user1.type = "users.userid";
	user1.value = "1";
	Prin user2;
	user2.type = "users.userid";
	user2.value = "2";
	Prin sender2;
	sender2.type = "privmsgs.senderid";
	sender2.value = "2";
	Prin rec1;
	rec1.type = "privmsgs.recid";
	rec1.value = "1";
	Prin mess9;
	mess9.type = "msgs.msgid";
	mess9.value = "9";
	Prin mess1;
	mess1.type = "msgs.msgid";
	mess1.value = "1";
	Prin text1;
	text1.type = "msgs.msgtext";
	text1.value = "hello world";

	string secretA = "secretA";
	secretA.resize(AES_KEY_BYTES);
	string secretB = "secretB";
	secretB.resize(AES_KEY_BYTES);

	assert_s(am->insertPsswd(name_a, secretA) == 0, "insert alice failed (a)");
	assert_s(am->insertPsswd(name_b, secretB) == 0, "insert bob failed (a)");

	am->insert(name_a, user1);
	am->insert(name_b, user2);
	am->insert(rec1, mess1);
	am->insert(sender2, mess1);
	am->insert(mess1, text1);

	assert_s(am->getKey(mess1).length() > 0, "can't access orphan key for message 1");

	cerr << "=============================================" << endl;
	cerr << "single-user tests" << endl;

	Prin u1;
	u1.type = "u.uid";
	u1.value = "1";
	Prin g5;
	g5.type = "g.gid";
	g5.value = "5";
	Prin f2;
	f2.type = "f.fid";
	f2.value = "2";

	assert_s(am->insertPsswd(alice, secretA) == 0, "insert alice failed (1)");
	am->insert(alice,u1);
	am->insert(u1,g5);
	am->insert(g5,f2);
	string alice_key = am->getKey(f2);
	myPrint(alice_key);
	cerr << endl;
	string f2_key1 = marshallBinary(alice_key);
	assert_s(alice_key.length() > 0, "alice can't access the forum 2 key");
	am->removePsswd(alice);
	assert_s(am->getKey(alice).length() == 0, "can access alice's key with no one logged in");
	assert_s(am->getKey(u1).length() == 0, "can access user 1 key with no one logged in");
	assert_s(am->getKey(g5).length() == 0, "can access group 5 key with no one logged in");
	assert_s(am->getKey(f2).length() == 0, "can access forum 2 key with no one logged in");
	assert_s(am->insertPsswd(alice, secretA) == 0, "insert alice failed (2)");
	alice_key = am->getKey(f2);
	assert_s(alice_key.length() > 0,"forum 2 key not found when alice logs on again");
	string f2_key2 = marshallBinary(alice_key);
	assert_s(f2_key1.compare(f2_key2) == 0, "forum 2 keys are not equal");

	assert_s(am->addEquals("g.gid", "foo.bar") < 0, "should not be able to alter meta here");
	assert_s(am->addAccess("g.gid", "foo.bar") < 0, "should not be able to alter meta here");
	assert_s(am->addGives("foo.bar") < 0, "should not be able to alter meta here");

	cerr << "=============================================" << endl;
	cerr << "multi-user tests" << endl;

	Prin bob;
	bob.type = "u.uname";
	bob.value = "bob";
	Prin u2;
	u2.type = "u.uid";
	u2.value = "2";
	Prin f3;
	f3.type = "f.fid";
	f3.value = "3";
	Prin a5;
	a5.type = "u.acc";
	a5.value = "5";
	Prin mlwork;
	mlwork.type = "x.mailing_list";
	mlwork.value = "work";

	assert_s(am->insertPsswd(bob, secretB) == 0, "insert bob failed (1)");
	am->insert(bob,u2);
	am->insert(u2,g5);
	assert_s(am->getKey(f2).length() > 0,"forum 2 key not accessible with both alice and bob logged on");
	am->removePsswd(alice);
	string bob_key = am->getKey(f2);
	assert_s(bob_key.length() > 0,"forum 2 key not accessible with bob logged on");
	string f2_key3 = marshallBinary(bob_key);
	assert_s(f2_key2.compare(f2_key3) == 0, "forum 2 key is not the same for bob as it was for alice");
	am->insert(g5,f3);
	bob_key = am->getKey(f3);
	string f3_key1 = marshallBinary(bob_key);
	assert_s(bob_key.length() > 0, "forum 3 key not acessible with bob logged on");
	am->removePsswd(bob);
	assert_s(am->getKey(alice).length() == 0, "can access alice's key with no one logged in");
	assert_s(am->getKey(bob).length() == 0, "can access bob's key with no one logged in");
	assert_s(am->getKey(u1).length() == 0, "can access user 1 key with no one logged in");
	assert_s(am->getKey(u2).length() == 0, "can access user 2 key with no one logged in");
	assert_s(am->getKey(g5).length() == 0, "can access group 5 key with no one logged in");
	assert_s(am->getKey(f2).length() == 0, "can access forum 2 key with no one logged in");
	assert_s(am->getKey(f3).length() == 0, "can access forum 3 key with no one logged in");
	assert_s(am->insertPsswd(alice, secretA) == 0, "insert alice failed (3)");
	alice_key = am->getKey(f3);
	assert_s(alice_key.length() > 0, "forum 3 key not accessible with alice logged on");
	string f3_key2 = marshallBinary(alice_key);
	assert_s(f3_key1.compare(f3_key2) == 0, "forum 3 key is not the same for alice as it was for bob");
	am->removePsswd(alice);
	am->insert(g5,mlwork);
	assert_s(am->getKey(mlwork).length() == 0, "can access mailing list work key with no one logged in");
	assert_s(am->insertPsswd(alice, secretA) == 0, "insert alice failed (4)");
	alice_key = am->getKey(mlwork);
	assert_s(alice_key.length() > 0, "mailing list work key inaccessible when alice is logged on");
	string mlwork_key1 = marshallBinary(alice_key);
	am->removePsswd(alice);
	assert_s(am->insertPsswd(bob, secretB) == 0, "insert bob failed (2)");
	bob_key = am->getKey(mlwork);
	assert_s(bob_key.length() > 0, "mailing list work key inaccessible when bob is logged on");
	string mlwork_key2 = marshallBinary(bob_key);
	assert_s(mlwork_key1.compare(mlwork_key2) == 0, "mailing list work key is not the same for bob as it was for alice");
	am->removePsswd(bob);

	cerr << "=============================================" << endl;
	cerr << "acylic graph, not tree tests" << endl;
	am->insert(g5,a5);
	assert_s(am->getKey(a5).length() == 0, "can access account 5 key with no one logged in");
	assert_s(am->insertPsswd(alice, secretA) == 0, "insert alice failed (5)");
	alice_key = am->getKey(a5);
	assert_s(alice_key.length() > 0, "account 5 key inaccessible when alice is logged on");
	string a5_key1 = marshallBinary(alice_key);
	am->removePsswd(alice);
	assert_s(am->insertPsswd(bob, secretB) == 0, "insert bob failed (3)");
	bob_key = am->getKey(a5);
	string a5_key2 = marshallBinary(bob_key);
	assert_s(a5_key1.compare(a5_key2) == 0, "account 5 key is not the same for bob as it was for alice");

	cerr << "=============================================" << endl;
	cerr << "orphan tests" << endl;

	am->removePsswd(bob);
	Prin m2;
	m2.type = "m.mess";
	m2.value = "2";
	Prin s6;
	s6.type = "m.sub";
	s6.value = "6";
	Prin m3;
	m3.type = "m.mess";
	m3.value = "3";
	Prin s4;
	s4.type = "m.sub";
	s4.value = "4";
	am->insert(m2, s6);
	string s6_key = am->getKey(s6);
	string m2_key = am->getKey(m2);
	string s6_key1 = marshallBinary(s6_key);
	string m2_key1 = marshallBinary(m2_key);
#if 0	/* XXX this is all broken because of char->string changes */
	assert_s(s6_key, "subject 6 key is not available after it has been inserted");
	assert_s(m2_key, "message 2 key (orphan) is not available after it has been inserted");
	am->insert(u2,m2);
	s6_key = am->getKey(s6);
	m2_key = am->getKey(m2);
	assert_s(!s6_key, "subject 6 key is available with bob not logged on");
	assert_s(!m2_key, "message 2 key is available with bob not logged on");
	assert_s(am->insertPsswd(bob, stringToUChar("secretB", AES_KEY_BYTES)) == 0, "insert bob failed (4)");
	s6_key = am->getKey(s6);
	m2_key = am->getKey(m2);
	string s6_key2 = marshallBinary(s6_key,AES_KEY_BYTES);
	string m2_key2 = marshallBinary(m2_key,AES_KEY_BYTES);
	assert_s(s6_key, "subject 6 key is not available with bob logged on");
	assert_s(s6_key1.compare(s6_key2) == 0, "subject 6 key is not equal when orphan and for bob");
	assert_s(m2_key, "message 2 key is not available with bob logged on");
	assert_s(m2_key1.compare(m2_key2) == 0, "message 2 key is not equal when orphan and for bob");
	am->insert(m3,s4);
	unsigned char * s4_key = am->getKey(s4);
	unsigned char * m3_key = am->getKey(m3);
	string s4_key1 = marshallBinary(s4_key, AES_KEY_BYTES);
	string m3_key1 = marshallBinary(m3_key, AES_KEY_BYTES);
	assert_s(s4_key, "subject 4 key is not available after it has been inserted");
	assert_s(m3_key, "message 3 key (orphan) is not available after it has been inserted");
	am->insert(u2,m3);
	s4_key = am->getKey(s4);
	m3_key = am->getKey(m3);
	string s4_key2 = marshallBinary(s4_key, AES_KEY_BYTES);
	string m3_key2 = marshallBinary(m3_key, AES_KEY_BYTES);
	assert_s(s4_key, "subject 4 key is not available with bob logged on");
	assert_s(s4_key1.compare(s4_key2) == 0, "subject 4 key is not equal when orphan and for bob");
	assert_s(m3_key, "message 3 key (orphan) is not available with bob logged on");
	assert_s(m3_key1.compare(m3_key2) == 0, "message 3 key is not equal when orphan and for bob");
	am->removePsswd(bob);
	s4_key = am->getKey(s4);
	m3_key = am->getKey(m3);
	assert_s(!s4_key, "subject 4 key is not available after it has been inserted");
	assert_s(!m3_key, "message 3 key (orphan) is not available after it has been inserted");
	assert_s(am->insertPsswd(bob, stringToUChar("secretB", AES_KEY_BYTES)) == 0, "insert bob failed (5)");
	s4_key = am->getKey(s4);
	m3_key = am->getKey(m3);
	string s4_key3 = marshallBinary(s4_key, AES_KEY_BYTES);
	string m3_key3 = marshallBinary(m3_key, AES_KEY_BYTES);
	assert_s(s4_key, "subject 4 key is not available with bob logged on");
	assert_s(s4_key1.compare(s4_key3) == 0, "subject 4 key is not equal when orphan and for bob (take 2)");
	assert_s(m3_key, "message 3 key (orphan) is not available with bob logged on");
	assert_s(m3_key1.compare(m3_key3) == 0, "message 3 key is not equal when orphan and for bob (take 2)");


	Prin m4;
	m4.type = "m.mess";
	m4.value = "4";
	Prin m5;
	m5.type = "m.mess";
	m5.value = "5";
	Prin s5;
	s5.type = "m.sub";
	s5.value = "5";
	Prin s7;
	s7.type = "m.sub";
	s7.value = "7";
	am->insert(m4,s6);
	unsigned char * m4_key = am->getKey(m4);
	s6_key = am->getKey(s6);
	string m4_key1 = marshallBinary(m4_key, AES_KEY_BYTES);
	string s6_key3 = marshallBinary(s6_key, AES_KEY_BYTES);
	assert_s(m4_key, "orphan message 4 key not available");
	assert_s(s6_key, "subject 6 key not available when orphan message 4 key available and bob logged on");
	assert_s(s6_key1.compare(s6_key3) == 0, "subject 6 key not the same");
	am->removePsswd(bob);
	m4_key = am->getKey(m4);
	s6_key = am->getKey(s6);
	string m4_key2 = marshallBinary(m4_key, AES_KEY_BYTES);
	string s6_key4 = marshallBinary(s6_key, AES_KEY_BYTES);
	assert_s(m4_key, "orphan message 4 key not available after bob logs off");
	assert_s(m4_key1.compare(m4_key2) == 0, "orphan message 4 key is different after bob logs off");
	assert_s(s6_key, "subject 6 key not available when orphan message 4 key available");
	assert_s(s6_key1.compare(s6_key3) == 0, "subject 6 key not the same after bob logs off");

	am->insert(m5,s5);
	am->insert(m5,s7);
	unsigned char * m5_key = am->getKey(m5);
	unsigned char * s5_key = am->getKey(s5);
	unsigned char * s7_key = am->getKey(s7);
	string m5_key1 = marshallBinary(m5_key, AES_KEY_BYTES);
	string s5_key1 = marshallBinary(s5_key, AES_KEY_BYTES);
	string s7_key1 = marshallBinary(s7_key, AES_KEY_BYTES);
	assert_s(m5_key, "message 5 key (orphan) not available");
	assert_s(s5_key, "subject 5 key (orphan) not available");
	assert_s(s7_key, "subject 7 key (orphan) not available");
	am->insert(u1,m5);
	m5_key = am->getKey(m5);
	s5_key = am->getKey(s5);
	s7_key = am->getKey(s7);
	assert_s(!am->getKey(alice), "alice is not logged off");
	assert_s(!m5_key, "message 5 key available with alice not logged on");
	assert_s(!s5_key, "subject 5 key available with alice not logged on");
	assert_s(!s7_key, "subject 7 key available with alice not logged on");
	assert_s(am->insertPsswd(alice, stringToUChar("secretA", AES_KEY_BYTES)) == 0, "insert alice failed (6)");
	m5_key = am->getKey(m5);
	s5_key = am->getKey(s5);
	s7_key = am->getKey(s7);
	string m5_key2 = marshallBinary(m5_key, AES_KEY_BYTES);
	string s5_key2 = marshallBinary(s5_key, AES_KEY_BYTES);
	string s7_key2 = marshallBinary(s7_key, AES_KEY_BYTES);
	assert_s(m5_key, "message 5 key not available with alice logged on");
	assert_s(m5_key1.compare(m5_key2) == 0, "message 5 key is different");
	assert_s(s5_key, "subject 5 key not available with alice logged on");
	assert_s(s5_key1.compare(s5_key2) == 0, "subject 5 key is different");
	assert_s(s7_key, "subject 7 key not available with alice logged on");
	assert_s(s7_key1.compare(s7_key2) == 0, "subject 7 key is different");


	Prin chris;
	chris.type = "u.uname";
	chris.value = "chris";
	Prin u3;
	u3.type = "u.uid";
	u3.value = "3";
	Prin m15;
	m15.type = "m.mess";
	m15.value = "15";
	Prin s24;
	s24.type = "m.sub";
	s24.value = "24";
	am->insert(u3, m15);
	unsigned char * m15_key = am->getKey(m15);
	assert_s(m15_key, "cannot access message 15 key (orphan)");
	string m15_key1 = marshallBinary(m15_key, AES_KEY_BYTES);
	unsigned char * u3_key = am->getKey(u3);
	assert_s(u3_key, "cannot access user 3 key (orphan)");
	string u3_key1 = marshallBinary(u3_key, AES_KEY_BYTES);
	am->insert(m15, s24);
	unsigned char * s24_key = am->getKey(s24);
	assert_s(s24_key, "cannot access subject 24 key (orphan)");
	string s24_key1 = marshallBinary(s24_key, AES_KEY_BYTES);
	assert_s(am->insertPsswd(chris, stringToUChar("secretC", AES_KEY_BYTES)) == 0, "insert chris failed (1)");
	unsigned char * chris_key = am->getKey(chris);
	assert_s(chris_key, "cannot access chris key with chris logged on");
	string chris_key1 = marshallBinary(chris_key, AES_KEY_BYTES);
	am->insert(chris, u3);
	chris_key = am->getKey(chris);
	assert_s(chris_key, "cannot access chris key after chris->u3 insert");
	string chris_key2 = marshallBinary(chris_key, AES_KEY_BYTES);
	assert_s(chris_key1.compare(chris_key2) == 0, "chris key is different for orphan and chris logged on");

	am->removePsswd(chris);
	assert_s(!am->getKey(chris), "can access chris key with chris offline");
	assert_s(!am->getKey(u3), "can access user 3 key with chris offline");
	assert_s(!am->getKey(m15), "can access message 15 key with chris offline");
	assert_s(!am->getKey(s24), "can access subject 24 key with chris offline");

	assert_s(am->insertPsswd(chris, stringToUChar("secretC", AES_KEY_BYTES)) == 0, "insert chris failed (2)");
	chris_key = am->getKey(chris);
	assert_s(chris_key, "cannot access chris key with chris logged on after logging off");
	string chris_key3 = marshallBinary(chris_key, AES_KEY_BYTES);
	assert_s(chris_key1.compare(chris_key3) == 0, "chris key is different for orphan and chris logged on after logging off");
	u3_key = am->getKey(u3);
	assert_s(u3_key, "cannot access user 3 key with chris logged on after logging off");
	string u3_key2 = marshallBinary(u3_key, AES_KEY_BYTES);
	assert_s(u3_key1.compare(u3_key2) == 0, "user 3 key is different for orphan and chris logged on after logging off");
	m15_key = am->getKey(m15);
	assert_s(m15_key, "cannot access message 15 key with chris logged on after logging off");
	string m15_key2 = marshallBinary(m15_key, AES_KEY_BYTES);
	assert_s(m15_key1.compare(m15_key2) == 0, "message 15 key is different for orphan and chris logged on after logging off");
	s24_key = am->getKey(s24);
	assert_s(s24_key, "cannot access subject 24 key with chris logged on after logging off");
	string s24_key2 = marshallBinary(s24_key, AES_KEY_BYTES);
	assert_s(s24_key1.compare(s24_key2) == 0, "subject 24 key is different for orphan and chris logged on after logging off");


	Prin s16;
	s16.type = "m.sub";
	s16.value = "16";
	unsigned char * s16_key = am->getKey(s16);
	string s16_key1 = marshallBinary(s16_key, AES_KEY_BYTES);
	assert_s(s16_key, "orphan subject 16 did not get a key generated for it");
	am->insert(m15, s16);
	s16_key = am->getKey(s16);
	string s16_key2 = marshallBinary(s16_key, AES_KEY_BYTES);
	assert_s(s16_key, "subject 16 does not have key being de-orphanized");
	assert_s(s16_key1.compare(s16_key2) == 0, "subject 16 has a different key after being orphanized");
	am->removePsswd(chris);
	assert_s(!am->getKey(s16), "can access subject 16 key with chris offline");
	assert_s(am->insertPsswd(chris, stringToUChar("secretC", AES_KEY_BYTES)) == 0, "insert chris failed (2)");	
	s16_key = am->getKey(s16);
	string s16_key3 = marshallBinary(s16_key, AES_KEY_BYTES);
	assert_s(s16_key, "subject 16 does not have key after chris logs off and on");
	assert_s(s16_key1.compare(s16_key2) == 0, "subject 16 has a different key after chris logs out and back in");

	cerr << "=============================================" << endl;
	cerr << "remove tests" << endl;
	assert_s(am->insertPsswd(bob, stringToUChar("secretB", AES_KEY_BYTES)) == 0, "insert bob failed (6)");
	s4_key = am->getKey(s4);
	assert_s(s4_key, "cannot access subject 4 key with bob logged on");
	string s4_key4 = marshallBinary(s4_key, AES_KEY_BYTES);
	assert_s(s4_key1.compare(s4_key4) == 0, "Subject 4 has changed");
	s6_key = am->getKey(s6);
	assert_s(s6_key, "cannot access subject 6 key with bob logged on");
	string s6_key5 = marshallBinary(s6_key, AES_KEY_BYTES);
	assert_s(s6_key1.compare(s6_key5) == 0, "Subject 6 has changed");
	m2_key = am->getKey(m2);
	assert_s(m2_key, "cannot access message 2 key with bob logged on");
	string m2_key3 = marshallBinary(m2_key, AES_KEY_BYTES);
	assert_s(m2_key1.compare(m2_key3) == 0, "Message 2 has changed");
	m3_key = am->getKey(m3);
	assert_s(m3_key, "cannot access message 3 key with bob logged on");
	string m3_key4 = marshallBinary(m3_key, AES_KEY_BYTES);
	assert_s(m3_key1.compare(m3_key4) == 0, "Message 3 has changed");
	unsigned char * u2_key = am->getKey(u2);
	assert_s(u2_key, "cannot access user 2 key with bob logged on");
	string u2_key1 = marshallBinary(u2_key, AES_KEY_BYTES);

	am->removePsswd(alice);
	unsigned char * g5_key = am->getKey(g5);
	assert_s(g5_key, "cannot access group 5 key with bob logged on");
	string g5_key1 = marshallBinary(g5_key, AES_KEY_BYTES);
	unsigned char * f2_key = am->getKey(f2);
	assert_s(f2_key, "cannot access forum 2 key with bob logged on");
	string f2_key4 = marshallBinary(f2_key, AES_KEY_BYTES);
	assert_s(f2_key1.compare(f2_key4) == 0, "Forum 2 key has changed");
	unsigned char * f3_key = am->getKey(f3);
	assert_s(f3_key, "cannot access forum 3 key with bob logged on");
	string f3_key3 = marshallBinary(f3_key, AES_KEY_BYTES);
	assert_s(f3_key1.compare(f3_key3) == 0, "Forum 3 key has changed");
	unsigned char * a5_key = am->getKey(a5);
	assert_s(a5_key, "cannot access account 5 key with bob logged on");
	string a5_key3 = marshallBinary(a5_key, AES_KEY_BYTES);
	assert_s(a5_key1.compare(a5_key3) == 0, "Account 5 key has changed");
	unsigned char * u1_key = am->getKey(u1);
	assert_s(!u1_key, "user 1 key available when Alice not logged on");
	assert_s(am->insertPsswd(alice, stringToUChar("secretA", AES_KEY_BYTES)) == 0, "insert alice failed (6)");

	am->remove(u2, g5);
	s4_key = am->getKey(s4);
	assert_s(s4_key, "cannot access subject 4 key with bob logged on");
	string s4_key5 = marshallBinary(s4_key, AES_KEY_BYTES);
	assert_s(s4_key1.compare(s4_key5) == 0, "Subject 4 has changed");
	s6_key = am->getKey(s6);
	assert_s(s6_key, "cannot access subject 6 key with bob logged on");
	string s6_key6 = marshallBinary(s6_key, AES_KEY_BYTES);
	assert_s(s6_key1.compare(s6_key6) == 0, "Subject 6 has changed");
	m2_key = am->getKey(m2);
	assert_s(m2_key, "cannot access message 2 key with bob logged on");
	string m2_key4 = marshallBinary(m2_key, AES_KEY_BYTES);
	assert_s(m2_key1.compare(m2_key4) == 0, "Message 2 has changed");
	m3_key = am->getKey(m3);
	assert_s(m3_key, "cannot access message 3 key with bob logged on");
	string m3_key5 = marshallBinary(m3_key, AES_KEY_BYTES);
	assert_s(m3_key1.compare(m3_key5) == 0, "Message 3 has changed");
	g5_key = am->getKey(g5);
	assert_s(g5_key, "cannot access group 5 key with alice logged on");
	string g5_key2 = marshallBinary(g5_key, AES_KEY_BYTES);
	assert_s(g5_key1.compare(g5_key2) == 0, "Group 5 key has changed");
	f2_key = am->getKey(f2);
	assert_s(f2_key, "cannot access forum 2 key with alice logged on");
	string f2_key5 = marshallBinary(f2_key, AES_KEY_BYTES);
	assert_s(f2_key1.compare(f2_key5) == 0, "Forum 2 key has changed");
	f3_key = am->getKey(f3);
	assert_s(f3_key, "cannot access forum 3 key with alice logged on");
	string f3_key4 = marshallBinary(f3_key, AES_KEY_BYTES);
	assert_s(f3_key1.compare(f3_key4) == 0, "Forum 3 key has changed");
	a5_key = am->getKey(a5);
	assert_s(a5_key, "cannot access account 5 key with alice logged on");
	string a5_key4 = marshallBinary(a5_key, AES_KEY_BYTES);
	assert_s(a5_key1.compare(a5_key4) == 0, "Account 5 key has changed");

	am->removePsswd(alice);
	g5_key = am->getKey(g5);
	assert_s(!g5_key, "group 5 key available when alice is logged off");
	a5_key = am->getKey(a5);
	assert_s(!a5_key, "account 5 key available when alice is logged off");
	f2_key = am->getKey(f2);
	assert_s(!f2_key, "forum 2 key available when alice is logged off");
	f3_key = am->getKey(f3);
	assert_s(!f3_key, "forum 3 key available when alice is logged off");

	assert_s(am->insertPsswd(chris, stringToUChar("secretC", AES_KEY_BYTES)) == 0, "insert chris failed (3)");
	s24_key = am->getKey(s24);
	assert_s(s24_key, "subject 24 key is not accessible with chris logged on");
	string s24_key3 = marshallBinary(s24_key, AES_KEY_BYTES);
	assert_s(s24_key1.compare(s24_key3) == 0, "subject 24 key is not the same");
	m15_key = am->getKey(m15);
	assert_s(m15_key, "message 15 key is not accessible with chris logged on");
	string m15_key3 = marshallBinary(m15_key, AES_KEY_BYTES);
	assert_s(m15_key1.compare(m15_key3) == 0, "message 15 key is not the same");
	u3_key = am->getKey(u3);
	assert_s(u3_key, "user 3 key is not accessible with chris logged on");
	string u3_key3 = marshallBinary(u3_key, AES_KEY_BYTES);
	assert_s(u3_key1.compare(u3_key3) == 0, "user 3 key is not the same");

	am->remove(u3,m15);
	s24_key = am->getKey(s24);
	assert_s(!s24_key, "subject 24 key is accessible after removal");
	m15_key = am->getKey(m15);
	assert_s(!m15_key, "message 15 key is accessible after removal");
	u3_key = am->getKey(u3);
	assert_s(u3_key, "user 3 key is not accessible with chris after u3->m15 removal");
	string u3_key4 = marshallBinary(u3_key, AES_KEY_BYTES);
	assert_s(u3_key1.compare(u3_key4) == 0, "user 3 key is not the same after u3->m15 removal");

	am->remove(g5,f3);
	assert_s(am->insertPsswd(alice, stringToUChar("secretA", AES_KEY_BYTES)) == 0, "insert alice failed (7)");
	g5_key = am->getKey(g5);
	assert_s(g5_key, "cannot access group 5 key with alice logged on");
	string g5_key3 = marshallBinary(g5_key, AES_KEY_BYTES);
	assert_s(g5_key1.compare(g5_key3) == 0, "Group 5 key has changed");
	f2_key = am->getKey(f2);
	assert_s(f2_key, "cannot access forum 2 key with alice logged on");
	string f2_key6 = marshallBinary(f2_key, AES_KEY_BYTES);
	assert_s(f2_key1.compare(f2_key6) == 0, "Forum 2 key has changed");
	a5_key = am->getKey(a5);
	assert_s(a5_key, "cannot access account 5 key with alice logged on");
	string a5_key5 = marshallBinary(a5_key, AES_KEY_BYTES);
	assert_s(a5_key1.compare(a5_key5) == 0, "Account 5 key has changed");  g5_key = am->getKey(g5);
	f3_key = am->getKey(f3);
	assert_s(!f3_key, "forum 3 key available when alice is logged off");

	am->removePsswd(bob);
	s6_key = am->getKey(s6);
	assert_s(s6_key, "subject 6 key, attached to orphan m4 not accessible");
	string s6_key7 = marshallBinary(s6_key, AES_KEY_BYTES);
	assert_s(s6_key1.compare(s6_key7) == 0, "subject 6 key has changed");
	m4_key = am->getKey(m4);
	assert_s(m4_key, "message 4 key (orpahn) not available");
	string m4_key3 = marshallBinary(m4_key, AES_KEY_BYTES);
	assert_s(m4_key1.compare(m4_key3) == 0, "message 4 key has changed");

	am->remove(m4,s6);
	m3_key = am->getKey(m3);
	assert_s(!m3_key, "message 3 key available when bob is logged off");
	m2_key = am->getKey(m2);
	assert_s(!m2_key, "message 2 key available when bob is logged off");
	s6_key = am->getKey(s6);
	assert_s(!s6_key, "subject 6 key available when bob is logged off");
	m4_key = am->getKey(m4);
	assert_s(m4_key, "message 4 key (orpahn) not available after remove");
	string m4_key4 = marshallBinary(m4_key, AES_KEY_BYTES);
	assert_s(m4_key1.compare(m4_key4) == 0, "message 4 key has changed after remove");

	cerr << "=============================================" << endl;
	cerr << "threshold tests" << endl;

	am->removePsswd(alice);
	string g50_key1;
	unsigned char * g50_key;
	for (unsigned int i = 6; i < 110; i++) {
		Prin group;
		group.type = "g.gid";
		group.value = marshallVal(i);
		am->insert(u3,group);
		if(i == 50) {
			g50_key = am->getKey(group);
			assert_s(g50_key, "could not access g50 key just after it's inserted");
			g50_key1 = marshallBinary(g50_key, AES_KEY_BYTES);
		}
	}

	am->removePsswd(chris);
	Prin g50;
	g50.type = "g.gid";
	g50.value = "50";
	g50_key = am->getKey(g50);
	assert_s(!g50_key, "g50 key available after chris logs off");
	assert_s(am->insertPsswd(chris, stringToUChar("secretC", AES_KEY_BYTES)) == 0, "insert chris failed (4)");
	PrinKey g50_pkey = am->getUncached(g50);
	assert_s(g50_pkey.len != 0, "can't access g50 key after chris logs back on");
	g50_key = am->getKey(g50);
	string g50_key2 = marshallBinary(g50_key,AES_KEY_BYTES);
	assert_s(g50_key1.compare(g50_key2) == 0, "group 50 key is different after chris logs on and off");

	for (unsigned int i = 6; i < 110; i++) {
		Prin group;
		group.type = "g.gid";
		group.value = marshallVal(i);
		am->remove(u3,group);
	}

	g50_key = am->getKey(g50);
	assert_s(!g50_key, "g50 key exists after the hundred group keys have been removed");

	am->~KeyAccess();

	


	/* AccessManager * am;

	// This test is no longer valid due to orphans.

	am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));

	am->addEquals("i.uid","u.uid");
	am->givesPsswd("u.uname");
	am->addAccessTo("u.uid", "u.uname");

    //alice, bob join
	am->insertPsswd("alice", stringToUChar("secretA", AES_KEY_BYTES));
	am->insertPsswd("bob", stringToUChar("secretB", AES_KEY_BYTES));

    assert_s(am->getKey("i.uid", "1") == NULL, "the key is not NULL");

    cerr << "passed i.uid test \n";

	am->finish();

	am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));

	//OUR EXAMPLE TEST
	 * */

	/* cerr << "=====================================\n";

  cout << "our example test" << endl;
  am->addAccessTo("g.gid","g.uid");

  am->addEquals("g.uid","u.uid");
  am->givesPsswd("u.uname");
  am->addAccessTo("u.uid", "u.uname");


  //alice, bob, chris join
  //unsigned char * palice = stringToUChar("111", AES_KEY_BYTES);
  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  am->insertPsswd("bob", stringToUChar("222", AES_KEY_BYTES));
  am->insertPsswd("chris", stringToUChar("333", AES_KEY_BYTES));

  am->insert(makeList("u.uid", "u.uname"), makeList("1","alice"));
  am->insert(makeList("u.uid", "u.uname"), makeList("2","bob"));
  am->insert(makeList("u.uid", "u.uname"), makeList("3","chris"));

  //alice is in group 11, bob is in group 22, chris in 11
  am->insert(makeList("g.gid", "g.uid"), makeList("11", "1"));
  am->insert(makeList("g.gid", "g.uid"), makeList("22", "2"));
  am->insert(makeList("g.gid", "g.uid"), makeList("11", "3"));


  //alice leaves
  cerr << "d\n";
  am->deletePsswd("alice");

  cerr << "e\n";
  unsigned char * keychris = am->getKey("g.gid", "11");

  cerr << "f\n";
  //alice comes back, chris leaves

  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  cerr << "g\n";
  am->deletePsswd("chris");

  unsigned char * keyalice = am->getKey("g.gid", "11");
  cerr << (keyalice == NULL) << " where true is " << true << endl;
  cerr << "h\n";
  assert_s(isEqual(keyalice, keychris, AES_KEY_BYTES), "alice/chris gid keys different");


  cerr << "j\n";
  //alice leaves as well
  am->deletePsswd("alice");
  assert_s(am->getKey("g.gid", "11") == NULL, "gid key should not be available when no user online");
  cerr << "i\n";
  assert_s(am->getKey("g.gid", "22") != NULL, "bob is online but key is null!");

  am->deletePsswd("bob");
  cerr << "j\n";

  assert_s(am->getKey("g.gid","22") == NULL, "bob left yet his gid key is still available");
  cerr << "k\n";



  am->finish();

  cerr << "our example OK\n";

  cerr << "LONG STRINGS OF EQUALITY TESTING!"  << endl;

  am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));

  am->givesPsswd("u.uname");
  am->addEquals("u.uid","p.uid");
  am->addEquals("p.uid","t.uid");
  am->addEquals("t.uid","c.uid");
  am->addEquals("c.uid","u.uid");
  am->addAccessTo("u.uid","u.uname");
  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  am->insert(makeList("u.uid","u.uname"), makeList("1","alice"));
  unsigned char * uukey = am->getKey("u.uid","1");

  assert_s(am->getKey("u.uid","1") != NULL,"u.uid should have key");
  assert_s(am->getKey("p.uid","1") != NULL,"p.uid should have key");
  assert_s(isEqual(am->getKey("p.uid","1"),uukey,AES_KEY_BYTES),"key not equal");
  assert_s(am->getKey("t.uid","1") != NULL,"t.uid should have key");
  assert_s(isEqual(am->getKey("t.uid","1"),uukey,AES_KEY_BYTES),"key not equal");
  assert_s(am->getKey("c.uid","1") != NULL,"c.uid should have key");
  assert_s(isEqual(am->getKey("c.uid","1"),uukey,AES_KEY_BYTES),"key not equal");

  am->finish();


  cerr << "Test\n";
  am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));


  am->addEquals("t1.id", "users.id");
  am->givesPsswd("users.username");
  am->addAccessTo("users.id", "users.username");
  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  am->deletePsswd("alice");
  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  am->insert(makeList("users.id", "users.username"), makeList("1", "alice"));
  assert_s(am->getKey("users.id", "1") != NULL, "access manager should have key");
  assert_s(am->getKey("t1.id", "1") != NULL, "access manager should have key");
  myPrint(am->getKey("users.id", "1"), AES_KEY_BYTES);

  am->finish();

  cerr << "\n";

  cerr << "TEST: users properly log out \n";

  am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));

  cerr << "1-----------------------------------------------" << endl;
  assert_s(0==am->addEquals("users.id", "t1.id"), "operation failed");
  assert_s(0==am->givesPsswd("users.username"), "operation failed");
  assert_s(0==am->addAccessTo("users.id", "users.username"), "operation failed");
  assert_s(0==am->addAccessTo("usergroup.gid", "usergroup.uid"), "operation failed");
  assert_s(0==am->addEquals("usergroup.gid", "g.gid"), "operation failed");
  assert_s(0==am->addEquals("usergroup.uid","users.id"), "operation failed");
  assert_s(0==am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES)), "operation failed");
  assert_s(0==am->insertPsswd("bob", stringToUChar("222", AES_KEY_BYTES)), "operation failed");
  assert_s(0==am->insert(makeList("users.id", "users.username"), makeList("1", "alice")), "operation failed");
  assert_s(0==am->insert(makeList("users.id", "users.username"), makeList("2", "bob")), "operation failed");

  assert_s(0==am->insert(makeList("usergroup.gid", "usergroup.uid"), makeList("1", "1")), "operation failed");
  assert_s(0==am->insert(makeList("usergroup.gid", "usergroup.uid"), makeList("1", "2")), "operation failed");
  cerr << "2-----------------------------------------------" << endl;
  unsigned char * key = am->getKey("usergroup.gid", "1");
  assert_s(key != NULL, "access manager should have key");

  assert_s(am->getKey("usergroup.uid", "1") != NULL, "user is online");
  assert_s(am->getKey("usergroup.uid", "2") != NULL, "user is online");

  am->deletePsswd("bob");

  unsigned char * key2 = am->getKey("usergroup.gid", "1");
  assert_s(key2 != NULL, "access manager should have key");
  assert_s(isEqual(key, key2, AES_KEY_BYTES), "keys should be equal");

  am->deletePsswd("alice");

  assert_s(am->getKey("usergroup.gid", "1") == NULL, "no one should have access now");
  assert_s(am->getKey("usergroup.uid", "1") == NULL, "no one should have access now");
  assert_s(am->getKey("usergroup.uid", "2") == NULL, "no one should have access now");

  //assert_s(am->hasAccessTo("t1.id").length() > 0, "at least users.username should have access to it");

  //assert_s(am->hasAccessTo("g.gid").length() > 0, "at least usergroup.uid should have access to it");

  assert_s(am->insert(makeList("users.id", "users.username"), makeList("3", "anonymous")) < 0, "operation failed");

  am->finish();

  cerr << "TESTS OK \n";


  cerr <<" ===========================\n TEST ORPHAN \n";

  am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));

  assert_s(0<=am->givesPsswd("u.uname"), "problem with gives psswd");

  assert_s(0<=am->addAccessTo("u.uid","u.uname"), "problem with addaccces");
  //sender and reciever of message mid
  assert_s(0<=am->addAccessTo("m.mid","m.sid"), "problem with addaccces");
  assert_s(0<=am->addAccessTo("m.mid","m.rid"), "problem with addaccces");

  assert_s(0<=am->addEquals("m.sid","u.uid"), "problem with addequals");
  assert_s(0<=am->addEquals("u.uid","m.rid"), "problem with addequals");


  unsigned char * key1 = am->getKey("m.mid", "1");

  assert_s(key1 != NULL, "should get an orphan principal's key");

  assert_s(0<=am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES)), "insert pss failed");

  assert_s(0<=am->insert(makeList("u.uid", "u.uname"), makeList("1", "alice")), "insert faield");

  assert_s(0<=am->insert(makeList("m.mid", "m.rid"), makeList("1", "1")), "insert failed");

  unsigned char * key11 = am->getKey("m.mid", "1");

  assert_s(isEqual(key11, key1, AES_KEY_BYTES), "keys should be equal");

  assert_s(0<=am->deletePsswd("alice"), "delete psswd failed");

  assert_s(am->getKey("m.mid", "1") == NULL, "should not be orphaned any more");


  cerr << "orphan test OK\n";

  am->finish();

  //return;


  am = new AccessManager(new Connect("localhost", "root", "letmein", "mysql"));

  cerr << "remove test \n";

  am->addAccessTo("g.gid","g.uid");
  am->addEquals("g.uid","u.uid");
  am->givesPsswd("u.uname");
  am->addAccessTo("u.uid", "u.uname");

  //alice, bob, chris join
  //unsigned char * palice = stringToUChar("111", AES_KEY_BYTES);
  am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));
  am->insertPsswd("bob", stringToUChar("222", AES_KEY_BYTES));
  am->insertPsswd("chris", stringToUChar("333", AES_KEY_BYTES));

  am->insert(makeList("u.uid", "u.uname"), makeList("1","alice"));
  am->insert(makeList("u.uid", "u.uname"), makeList("2","bob"));
  am->insert(makeList("u.uid", "u.uname"), makeList("3","chris"));

  //alice is in group 11, bob is in group 22, chris in 11
  am->insert(makeList("g.gid", "g.uid"), makeList("11", "1"));
  am->insert(makeList("g.gid", "g.uid"), makeList("22", "2"));
  am->insert(makeList("g.gid", "g.uid"), makeList("11", "3"));

  //am->insertPsswd("alice", stringToUChar("111", AES_KEY_BYTES));

  assert_s(am->getKey("g.gid", "11") != NULL, "gid key should be available for Alice");

  //remove Alice's permission
  am->remove(makeList("g.gid", "g.uid"), makeList("11","1"));

  //I think this should be like so
  assert_s(am->getKey("g.gid", "11") != NULL, "Chris should still have permission");

  am->insert(makeList("g.gid", "g.uid"), makeList("11", "1"));

  assert_s(am->getKey("g.gid", "11") != NULL, "gid key should be available for Alice");

  //remove Alice's permission and log Chris off
  am->remove(makeList("g.gid", "g.uid"), makeList("11","1"));
  am->deletePsswd("chris");

  assert_s(am->getKey("g.gid", "11") == NULL, "gid key not should be available for Alice");

  am->finish();
	 */

#endif	/* XXX end of broken */

}



void testTrace(int argc, char ** argv) {

	if (argc < 5) {
		cerr << "usage: ./test trace createsfile fileoftrace  noofinstr [outputonion] \n";
		return;
	}

	bool outputOnions = false;
	if (argc == 6) {
		outputOnions = argv[4];
	}

	string masterKey =  BytesFromInt(mkey, AES_KEY_BYTES);
	EDBClient * cl;

	cl = new EDBClient("localhost", "root", "letmein", "phpbb", masterKey, 5123);

	cl->VERBOSE = false;

	//cl->plain_execute("DROP TABLE IF EXISTS phpbb_acl_groups,phpbb_acl_options,phpbb_acl_roles,phpbb_acl_roles_data,phpbb_acl_users,phpbb_attachments,phpbb_banlist,phpbb_bbcodes,phpbb_bookmarks,phpbb_bots,phpbb_config,phpbb_confirm,phpbb_disallow,phpbb_drafts,phpbb_extension_groups,phpbb_extensions,phpbb_forums,phpbb_forums_access,phpbb_forums_track,phpbb_forums_watch,phpbb_groups,phpbb_icons,phpbb_lang,phpbb_log,phpbb_moderator_cache,phpbb_modules,phpbb_poll_options,phpbb_poll_votes,phpbb_posts,phpbb_privmsgs,phpbb_privmsgs_folder,phpbb_privmsgs_rules,phpbb_privmsgs_to,phpbb_profile_fields,phpbb_profile_fields_data,phpbb_profile_fields_lang,phpbb_profile_lang,phpbb_ranks,phpbb_reports,phpbb_reports_reasons,phpbb_search_results,phpbb_search_wordlist,phpbb_search_wordmatch,phpbb_sessions,phpbb_sessions_keys,phpbb_sitelist,phpbb_smilies,phpbb_styles,phpbb_styles_imageset,phpbb_styles_imageset_data,phpbb_styles_template,phpbb_styles_template_data,phpbb_styles_theme,phpbb_topics,phpbb_topics_posted,phpbb_topics_track,phpbb_topics_watch,phpbb_user_group, phpbb_users, phpbb_warnings, phpbb_words, phpbb_zebra;");


	ifstream createsfile(argv[2]);
	ifstream tracefile(argv[3]);
	string query;

	int noinstr = atoi(argv[4]);


	if (!createsfile.is_open()) {
		cerr << "cannot open " << argv[2] << "\n";
		exit(1);
	}

	while (!createsfile.eof()) {
		getline(createsfile, query);
		cerr << "line is < " << query << ">\n";
		if (query.length() < 3) { continue; }
		//list<const char *> q = cl->rewriteEncryptQuery(getCStr(query), rb);
		//assert_s(q.size() == 1, "query translated has more than one query or no queries;");
		list<const char *> res = cl->rewriteEncryptQuery(getCStr(query));
		//cerr << "problem with query!\n";
		assert_s(res.size() == 1, "query did not return one");
		//cout << q.front() << "\n";

	}
	cerr << "creates ended \n";

	if (!tracefile.is_open()) {
		cerr << "cannot open " << argv[3] << "\n";
		exit(1);
	}


	struct timeval starttime, endtime;

	gettimeofday(&starttime, NULL);

	for (int i = 0; i <noinstr;i++) {

		if (!tracefile.eof()) {
			getline(tracefile, query);
			//if ((i<1063000) && (i>17)) {continue;}
			//cerr << "line is < " << query << ">\n";
			if (i % 100 == 0) {cerr << i << "\n";}
			if (query.length() < 3) { continue; }
			//list<const char *> q = cl->rewriteEncryptQuery(getCStr(query), rb);
			//assert_s(q.size() == 1, "query translated has more than one query or no queries;");
			if (!cl->execute(getCStr(query))) {
				cerr << "problem with query!\n";
			}
			//cout << q.front() << "\n";
		} else {
			cerr << "instructions ended \n";
			break;
		}
	}

	gettimeofday(&endtime, NULL);

	cout << (noinstr*1.0/timeInSec(starttime,endtime)) << "\n";

	//cerr << "DONE with trace \n";

	if (outputOnions) {
		cerr << "outputting state of onions ... \n";
		cl->outputOnionState();
	}

	tracefile.close();


}

void testPKCS() {

	PKCS * pk,* sk;
	CryptoManager::generateKeys(pk, sk);
	assert_s(pk != NULL, "pk is null");
	assert_s(sk != NULL, "pk is null");

	string pkbytes = CryptoManager::marshallKey(pk, true);

	assert_s(pkbytes == CryptoManager::marshallKey(CryptoManager::unmarshallKey(pkbytes, 1), 1), "marshall does not work");

	string skbytes = CryptoManager::marshallKey(sk, false);

	assert_s(skbytes == CryptoManager::marshallKey(CryptoManager::unmarshallKey(skbytes, 0), 0), "marshall does not work");


	char msg[] = "Hello world";

	string enc = CryptoManager::encrypt(pk, msg);
	string dec = CryptoManager::decrypt(sk, enc);
	assert_s(msg == dec, "decryption is not original msg");

	cerr << "msg" << dec << "\n";
}


int main(int argc, char ** argv) {


	if (argc == 1) {
		interactiveTest();
		return 0;
	}

	if (strcmp(argv[1], "single") == 0) {
		TestSinglePrinc::run(argc, argv);
	}

	if (strcmp(argv[1], "autoinc") == 0) {
		autoIncTest();
		return 0;
	}

	if (strcmp(argv[1], "trace") == 0) {
		testTrace(argc, argv);
		return 0;
	}

	if (strcmp(argv[1], "parseaccess") == 0) {
		testParseAccess();
		return 0;
	}

	if (strcmp(argv[1], "crypto") == 0) {
		testCrypto();
		return 0;
	}

	if (strcmp(argv[1], "access") == 0) {
		accessManagerTest();
		return 0;
	}

	if (strcmp(argv[1], "Paillier") == 0) {
		testPaillier();
		return 0;
	}

	if (strcmp(argv[1], "Crypto") == 0) {
		testCrypto();
		return 0;
	}

	if (strcmp(argv[1], "Utils") == 0) {

		testUtils();
		return 0;
	}
	if (strcmp(argv[1], "shell") == 0) {

		interactiveTest();
		return 0;
	}

	if (strcmp(argv[1], "tables") == 0) {
		if (argc == 2) {
			encryptionTablesTest();
			return 0;
		} else {
			cerr << "usage ./test tables ";
		}
	}

	if (strcmp(argv[1], "pkcs") == 0) {
		testPKCS();
		return 0;
	}

/*	if (strcmp(argv[1], "train") == 0) {
		test_train();
		return 0;
	}*/
/*		if (strcmp(argv[1], "trace") == 0) {
			if (argc != 4) { cerr << "usage ./test trace file noqueries isSecure ";}
			runTrace(argv[2], atoi(argv[3]), atoi(argv[4]));
			return 0;
		} */ /*
	if (strcmp(argv[1], "convert") == 0) {
		convertQueries();
		return 0;
	}

	if (strcmp(argv[1], "instance") == 0) {
		createInstance();
		return 0;
	}
		 */
/*
		if (strcmp(argv[1], "convertdump") == 0) {
			convertDump();
			return 0;
		}
 */
/*	if (strcmp(argv[1], "load") == 0) {
		if (argc != 8) {
			cerr << "usage: test load noWorkers totalLines logFreq file workeri1 workeri2\n";
			exit(1);
		}
		string filein = argv[5];
		cerr << "input file is " << argv[5] << "\n";
		parallelLoad(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), filein, atoi(argv[6]), atoi(argv[7]));
		return 0;
	}

	//int noWorkers, int noRepeats, int logFreq, int totalLines, string dfile, bool hasTransac
	if (strcmp(argv[1], "throughput") == 0) {

		if (argc != 9) {
			cerr << "usage: test throughput noWorkers noRepeats logFreq totalLines queryFile isSecure hasTransac \n";
			exit(1);
		}
		simpleThroughput(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), string(argv[6]), atoi(argv[7]), atoi(argv[8]));
	}

	if (strcmp(argv[1], "latency") == 0) {
			// queryFile, maxQueries, logFreq, isSecure, isVerbose
			if (argc != 7) {
				cerr << "usage: test latency queryFile maxQue logFreq isSecure isVerbose \n";
				exit(1);
			}
			latency(string(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));
	}
 */	/*
	if (strcmp(argv[1], "integration") == 0){
		testEDBClient();
		return 0;
	}
	cerr << "unknown option\n";


	//testCryptoManager();
	//testEDBClient();
	//tester t = tester("cryptdb", randomBytes(AES_KEY_BYTES));
	//t.testClientParser();

	//tester t = tester("cryptdb");
	//t.testMarshallBinary();

	//microEvaluate(argc, argv); //microEvaluate
	//test_OPE();
	//test_HGD();
	//test_EDBClient_noSecurity();
	//evaluateMetrics(argc, argv);
  */
	if (strcmp(argv[1], "aes") == 0) {
		evaluate_AES(argc, argv);
	}
}
