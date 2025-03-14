// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinrpc.h"
#include "base58.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "sync.h"
#include "ui_interface.h"
#include "util.h"

#undef printf
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <chrono>
#include <list>
#include <thread>

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;

void ThreadRPCServer2();

static std::string strRPCUserColonPass;

const Object emptyobj;

boost::atomic_bool fRpcListening{false};

Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}

void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out, bool fIncludeHex)
{
    txnouttype             type;
    vector<CTxDestination> addresses;
    int                    nRequired;

    out.push_back(Pair("asm", scriptPubKey.ToString()));

    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(CTxDB(), scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));
    out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    Array a;
    for (const CTxDestination& addr : addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void RPCTypeCheck(const Array& params, const list<Value_type>& typesExpected, bool fAllowNull)
{
    unsigned int i = 0;
    for (Value_type t : typesExpected) {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == null_type)))) {
            string err =
                fmt::format("Expected type {}, got {}", Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheck(const Object& o, const map<string, Value_type>& typesExpected, bool fAllowNull)
{
    for (const PAIRTYPE(const string, Value_type) & t : typesExpected) {
        const Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == null_type)
            throw JSONRPCError(RPC_TYPE_ERROR, fmt::format("Missing {}", t.first));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type)))) {
            string err = fmt::format("Expected type {} for {}, got {}", Value_type_name[t.second],
                                     t.first, Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

CAmount AmountFromValue(const Value& value)
{
    CAmount nAmount = 0;
    if (value.type() != real_type && value.type() != int_type && value.type() != str_type)
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    if (value.type() == str_type) {
        if (!ParseFixedPoint(value.get_str(), 8, &nAmount))
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    } else {
        double dAmount = value.get_real();
        nAmount        = roundint64(dAmount * COIN);
    }
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return nAmount;
}

NTP1Int NTP1AmountFromValue(const Value& value)
{
    NTP1Int nAmount = 0;
    if (value.type() != int_type && value.type() != str_type) {
        throw JSONRPCError(RPC_TYPE_ERROR, "NTP1 Amount is not a number or string");
    }
    if (value.type() == Value_type::str_type) {
        nAmount = NTP1Int(value.get_str());
    } else if (value.type() == Value_type::int_type) {
        nAmount = value.get_int64();
    }
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid amount: " + ::ToString(nAmount));
    }
    return nAmount;
}

Value ValueFromAmount(const CAmount& amount) { return Value(std::stod(FP_IntToDecimal(amount, 8))); }

//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
uint256 ParseHashV(const Value& v, const string& strName)
{
    std::string strHex;
    if (v.type() == json_spirit::str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strName + " must be hexadecimal string (not '" + strHex + "')");
    if (64 != strHex.length())
        throw JSONRPCError(RPC_INVALID_PARAMETER, fmt::format("{} must be of length {} (not {})",
                                                              strName.c_str(), 64, strHex.length()));
    uint256 result;
    result.SetHex(strHex);
    return result;
}

uint256 ParseHashO(const Object& o, string strKey) { return ParseHashV(find_value(o, strKey), strKey); }

vector<unsigned char> ParseHexV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strName + " must be hexadecimal string (not '" + strHex + "')");
    return ParseHex(strHex);
}

vector<unsigned char> ParseHexO(const Object& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

///
/// Note: This interface may still be subject to change.
///

string CRPCTable::help(string strCommand) const
{
    string          strRet;
    set<rpcfn_type> setDone;
    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin();
         mi != mapCommands.end(); ++mi) {
        const CRPCCommand* pcmd      = mi->second;
        string             strMethod = mi->first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        try {
            Array      params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        } catch (std::exception& e) {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = fmt::format("help: unknown command: {}\n", strCommand.c_str());
    strRet = strRet.substr(0, strRet.size() - 1);
    return strRet;
}

Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error("help [command]\n"
                            "List commands, or get help for a command.");

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return tableRPC.help(strCommand);
}

Value stop(const Array& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach´ boolean argument
    if (fHelp || params.size() > 1)
        throw runtime_error("stop\n"
                            "Stop neblio server.");

    // Shutdown will take long enough that the response should get back
    StartShutdown();
    return "neblio server stopping";
}

Value uptime(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error("uptime\n"
                            "Returns the total uptime of the server.\n");

    return GetTime() - GetStartupTime();
}

//
// Call Table
//

// clang-format off
static const CRPCCommand vRPCCommands[] =
{ //  name                         function                    safemd  unlocked
  //  ------------------------     -----------------------     ------  --------
    { "help",                      &help,                      true,   true  },
    { "stop",                      &stop,                      true,   true  },
    { "uptime",                    &uptime,                    false,  false },
    { "getbestblockhash",          &getbestblockhash,          true,   false },
    { "getblockcount",             &getblockcount,             true,   false },
    { "waitforblockheight",        &waitforblockheight,        true,   false },
    { "getconnectioncount",        &getconnectioncount,        true,   false },
    { "addnode",                   &addnode,                   true,   false },
    { "disconnectnode",            &disconnectnode,            true,   false },
    { "setmocktime",               &setmocktime,               false,  false },
    { "getpeerinfo",               &getpeerinfo,               true,   false },
    { "getdifficulty",             &getdifficulty,             true,   false },
    { "getinfo",                   &getinfo,                   true,   false },
    { "getsubsidy",                &getsubsidy,                true,   false },
    { "getmininginfo",             &getmininginfo,             true,   false },
    { "getstakinginfo",            &getstakinginfo,            true,   false },
    { "getnewaddress",             &getnewaddress,             true,   false },
    { "addledgeraddress",          &addledgeraddress,          true,   false },
    { "verifyledgeraddress",       &verifyledgeraddress,       true,   false },
    { "getledgeraccount",          &getledgeraccount,          true,   true  },
    { "udtoneblioaddress",         &udtoneblioaddress,         true,   false },
    { "getnewpubkey",              &getnewpubkey,              true,   false },
    { "getaccountaddress",         &getaccountaddress,         true,   false },
    { "delegatestake",             &delegatestake,             true,   false },
    { "listdelegators",            &listdelegators,            true,   false },
    { "delegatoradd",              &delegatoradd,              true,   false },
    { "liststakingaddresses",      &liststakingaddresses,      true,   false },
    { "delegatorremove",           &delegatorremove,           true,   false },
    { "rawdelegatestake",          &rawdelegatestake,          true,   false },
    { "listcoldutxos",             &listcoldutxos,             true,   false },
    { "setaccount",                &setaccount,                true,   false },
    { "getaccount",                &getaccount,                false,  false },
    { "getaddressesbyaccount",     &getaddressesbyaccount,     true,   false },
    { "sendtoaddress",             &sendtoaddress,             false,  false },
    { "sendntp1toaddress",         &sendntp1toaddress,         false,  false },
    { "getreceivedbyaddress",      &getreceivedbyaddress,      false,  false },
    { "getreceivedbyaccount",      &getreceivedbyaccount,      false,  false },
    { "listreceivedbyaddress",     &listreceivedbyaddress,     false,  false },
    { "listreceivedbyaccount",     &listreceivedbyaccount,     false,  false },
    { "backupwallet",              &backupwallet,              true,   false },
    { "keypoolrefill",             &keypoolrefill,             true,   false },
    { "getwalletinfo",             &getwalletinfo,             true,   false },
    { "getrawchangeaddress",       &getrawchangeaddress,       true,   false },
    { "walletpassphrase",          &walletpassphrase,          true,   false },
    { "walletpassphrasechange",    &walletpassphrasechange,    false,  false },
    { "walletlock",                &walletlock,                true,   false },
    { "encryptwallet",             &encryptwallet,             false,  false },
    { "validateaddress",           &validateaddress,           true,   false },
    { "validatepubkey",            &validatepubkey,            true,   false },
    { "getbalance",                &getbalance,                false,  false },
    { "getdelegatedbalance",       &getdelegatedbalance,       false,  false },
    { "getcoldstakingbalance",     &getcoldstakingbalance,     false,  false },
    { "getbalance",                &getbalance,                false,  false },
    { "getunconfirmedbalance",     &getunconfirmedbalance,     false,  false },
    { "getntp1balances",           &getntp1balances,           false,  false },
    { "getntp1balance",            &getntp1balance,            false,  false },
    { "abandontransaction",        &abandontransaction,        false,  false },
    { "move",                      &movecmd,                   false,  false },
    { "sendfrom",                  &sendfrom,                  false,  false },
    { "sendmany",                  &sendmany,                  false,  false },
    { "addmultisigaddress",        &addmultisigaddress,        false,  false },
    { "addredeemscript",           &addredeemscript,           false,  false },
    { "getrawmempool",             &getrawmempool,             true,   false },
    { "calculateblockhash",        &calculateblockhash,        false,  false },
    { "gettxout",                  &gettxout,                  false,  false },
    { "listvotes",                 &listvotes,                 false,  false },
    { "castvote",                  &castvote,                  false,  false },
    { "cancelallvotesofproposal",  &cancelallvotesofproposal,  false,  false },
    { "getblock",                  &getblock,                  false,  false },
    { "getblockbynumber",          &getblockbynumber,          false,  false },
    { "getblockhash",              &getblockhash,              false,  false },
    { "gettransaction",            &gettransaction,            false,  false },
    { "listtransactions",          &listtransactions,          false,  false },
    { "listaddressgroupings",      &listaddressgroupings,      false,  false },
    { "signmessage",               &signmessage,               false,  false },
    { "verifymessage",             &verifymessage,             false,  false },
    { "getwork",                   &getwork,                   true,   false },
    { "getworkex",                 &getworkex,                 true,   false },
    { "listaccounts",              &listaccounts,              false,  false },
    { "settxfee",                  &settxfee,                  false,  false },
    { "getblocktemplate",          &getblocktemplate,          true,   false },
    { "submitblock",               &submitblock,               false,  false },
    { "generateblockwithkey",      &generateblockwithkey,      false,  false },
    { "generatepos",               &generatepos,               false,  false },
    { "generate",                  &generate,                  false,  false },
    { "generatetoaddress",         &generatetoaddress,         false,  false },
    { "listsinceblock",            &listsinceblock,            false,  false },
    { "dumpprivkey",               &dumpprivkey,               false,  false },
    { "dumppubkey",                &dumppubkey,                false,  false },
    { "dumpwallet",                &dumpwallet,                true,   false },
    { "importwallet",              &importwallet,              false,  false },
    { "importprivkey",             &importprivkey,             false,  false },
    { "decodentp1script",          &decodentp1script,          false,  false },
    { "listunspent",               &listunspent,               false,  false },
    { "getrawtransaction",         &getrawtransaction,         false,  false },
    { "createrawtransaction",      &createrawtransaction,      false,  false },
    { "createrawntp1transaction",  &createrawntp1transaction,  false,  false },
    { "issuenewntp1token",         &issuenewntp1token,         false,  false },
    { "decoderawtransaction",      &decoderawtransaction,      false,  false },
    { "decodescript",              &decodescript,              false,  false },
    { "getscriptpubkeyfromaddress",&getscriptpubkeyfromaddress,false,  false },
    { "getscriptpubkeyforp2cs",    &getscriptpubkeyforp2cs,    false,  false },
    { "signrawtransaction",        &signrawtransaction,        false,  false },
    { "sendrawtransaction",        &sendrawtransaction,        false,  false },
    { "reservebalance",            &reservebalance,            false,  true  },
    { "resendtx",                  &resendtx,                  false,  true  },
    { "makekeypair",               &makekeypair,               false,  true  },
    { "sendalert",                 &sendalert,                 false,  false },
    { "exportblockchain",          &exportblockchain,          false,  false },
    { "getblockchaininfo",         &getblockchaininfo,         false,  false },
    { "getblockheader",            &getblockheader,            false,  false },
    { "syncwithvalidationinterfacequeue", &syncwithvalidationinterfacequeue, true, false },
};
// clang-format on

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++) {
        const CRPCCommand* pcmd;

        pcmd                    = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand* CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string, string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: neblio-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    BOOST_FOREACH (const PAIRTYPE(string, string) & item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char   buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string     locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want POSIX (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED)
        return fmt::format("HTTP/1.0 401 Authorization Required\r\n"
                           "Date: {}\r\n"
                           "Server: neblio-json-rpc/{}\r\n"
                           "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: 296\r\n"
                           "\r\n"
                           "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
                           "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
                           "<HTML>\r\n"
                           "<HEAD>\r\n"
                           "<TITLE>Error</TITLE>\r\n"
                           "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
                           "</HEAD>\r\n"
                           "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
                           "</HTML>\r\n",
                           rfc1123Time(), FormatFullVersion());
    const char* cStatus;
    if (nStatus == HTTP_OK)
        cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST)
        cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN)
        cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND)
        cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR)
        cStatus = "Internal Server Error";
    else
        cStatus = "";
    return fmt::format("HTTP/1.1 {} {}\r\n"
                       "Date: {}\r\n"
                       "Connection: {}\r\n"
                       "Content-Length: {}\r\n"
                       "Content-Type: application/json\r\n"
                       "Server: neblio-json-rpc/{}\r\n"
                       "\r\n"
                       "{}",
                       nStatus, cStatus, rfc1123Time(), keepalive ? "keep-alive" : "close",
                       strMsg.size(), FormatFullVersion(), strMsg);
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int& proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;
    proto           = 0;
    const char* ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != nullptr)
        proto = atoi(ver + 7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    while (true) {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos) {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon + 1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nProto  = 0;
    int nStatus = ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0) {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive")) {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6);
    boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    return TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply = JSONRPCReplyObj(result, error, id);
    return write_string(Value(reply), false) + "\n";
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code    = find_value(objError, "code").get_int();
    if (code == RPC_INVALID_REQUEST)
        nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND)
        nStatus = HTTP_NOT_FOUND;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6() && (address.to_v6().is_v4_compatible() || address.to_v6().is_v4_mapped()))
        return ClientAllowed(address.to_v6().to_v4());

    if (address == asio::ip::address_v4::loopback() || address == asio::ip::address_v6::loopback() ||
        (address.is_v4()
         // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
         && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
        return true;

    const string             strAddress = address.to_string();
    std::vector<std::string> rpcallowipVec =
        mapMultiArgs.get("-rpcallowip").value_or(std::vector<std::string>());
    const vector<string>& vAllow = rpcallowipVec;
    BOOST_FOREACH (string strAllow, vAllow)
        if (WildcardMatch(strAddress, strAllow))
            return true;
    return false;
}

//
// IOStream device that speaks SSL but can also speak non-SSL
//
template <typename Protocol>
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional>
{
public:
    SSLIOStreamDevice(asio::ssl::stream<typename Protocol::socket>& streamIn, bool fUseSSLIn)
        : stream(streamIn)
    {
        fUseSSL        = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake)
            return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL)
            return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL)
            return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
#if BOOST_VERSION >= 107000
        auto executionContextOrExecutor = stream.get_executor();
#else
        auto& executionContextOrExecutor = stream.get_io_service();
#endif

        _Pragma(NEBLIO_DIAGNOSTIC_PUSH);
        _Pragma(NEBLIO_HIDE_SHADOW_WARNING);

        ip::tcp::resolver           resolver(executionContextOrExecutor);
        ip::tcp::resolver::query    query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code   error = asio::error::host_not_found;

        _Pragma(NEBLIO_DIAGNOSTIC_POP);

        while (error && endpoint_iterator != end) {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
    }

private:
    bool                                          fNeedHandshake;
    bool                                          fUseSSL;
    asio::ssl::stream<typename Protocol::socket>& stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}

    virtual std::iostream& stream()                       = 0;
    virtual std::string    peer_address_to_string() const = 0;
    virtual void           close()                        = 0;
};

// Although this "Executor" can be an ExecutionContext, we use this just for backward compatibility with
// older boost versions
template <typename Protocol, typename Executor>
class AcceptedConnectionImpl : public AcceptedConnection
{
public:
    AcceptedConnectionImpl(Executor& io_service, ssl::context& context, bool fUseSSL)
        : sslStream(io_service, context), _d(sslStream, fUseSSL), _stream(_d)
    {
    }

    virtual std::iostream& stream() { return _stream; }

    virtual std::string peer_address_to_string() const { return peer.address().to_string(); }

    virtual void close() { _stream.close(); }

    typename Protocol::endpoint                  peer;
    asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol>                    _d;
    iostreams::stream<SSLIOStreamDevice<Protocol>> _stream;
};

static bool InitRPCAuthentication()
{
    if (GetArg("-rpcpassword", "") == "") {
        NLog.write(b_sev::info, "No rpcpassword set - using random cookie authentication");
        if (!GenerateAuthCookie(&strRPCUserColonPass)) {
            uiInterface.ThreadSafeMessageBox(
                _("Error: A fatal internal error occurred while generating the authentication cookie, "
                  "see debug.log for details"), // Same message
                                                // as AbortNode
                "", CClientUIInterface::OK | CClientUIInterface::MODAL);
            return false;
        }
    } else {
        strRPCUserColonPass = GetArg("-rpcuser", "") + ":" + GetArg("-rpcpassword", "");
    }
    return true;
}

void ThreadRPCServer()
{
    // Make this thread recognisable as the RPC listener
    RenameThread("neblio-rpclist");

    try {
        vnThreadsRunning[THREAD_RPCLISTENER]++;
        ThreadRPCServer2();
        vnThreadsRunning[THREAD_RPCLISTENER]--;
    } catch (std::exception& e) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    NLog.write(b_sev::info, "ThreadRPCServer exited");
}

void ThreadRPCServer3(boost::shared_ptr<AcceptedConnection> conn);

// Forward declaration required for RPCListen
template <typename Protocol>
static void RPCAcceptHandler(boost::shared_ptr<basic_socket_acceptor<Protocol>> acceptor,
                             ssl::context& context, bool fUseSSL,
                             boost::shared_ptr<AcceptedConnection> conn,
                             const boost::system::error_code&      error);

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
template <typename Protocol>
static void RPCListen(boost::shared_ptr<basic_socket_acceptor<Protocol>> acceptor, ssl::context& context,
                      const bool fUseSSL)
{
#if BOOST_VERSION >= 107000
    auto executionContextOrExecutor = acceptor->get_executor();
#else
    auto& executionContextOrExecutor = acceptor->get_io_service();
#endif

    using ExecutorType = typename std::remove_reference<decltype(executionContextOrExecutor)>::type;

    // Accept connection
    boost::shared_ptr<AcceptedConnectionImpl<Protocol, ExecutorType>> conn =
        boost::shared_ptr<AcceptedConnectionImpl<Protocol, ExecutorType>>(
            new AcceptedConnectionImpl<Protocol, ExecutorType>(executionContextOrExecutor, context,
                                                               fUseSSL));

    acceptor->async_accept(conn->sslStream.lowest_layer(), conn->peer,
                           boost::bind(&RPCAcceptHandler<Protocol>, acceptor, boost::ref(context),
                                       fUseSSL, conn, boost::asio::placeholders::error));
}

/**
 * Accept and handle incoming connection.
 */
template <typename Protocol>
static void RPCAcceptHandler(boost::shared_ptr<basic_socket_acceptor<Protocol>> acceptor,
                             ssl::context& context, const bool fUseSSL,
                             boost::shared_ptr<AcceptedConnection> conn,
                             const boost::system::error_code&      error)
{
    vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != asio::error::operation_aborted && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

#if BOOST_VERSION >= 107000
    auto executionContextOrExecutor = acceptor->get_executor();
#else
    auto& executionContextOrExecutor = acceptor->get_io_service();
#endif

    using ExecutorType = typename std::remove_reference<decltype(executionContextOrExecutor)>::type;

    boost::shared_ptr<AcceptedConnectionImpl<ip::tcp, ExecutorType>> tcp_conn =
        boost::dynamic_pointer_cast<AcceptedConnectionImpl<ip::tcp, ExecutorType>>(conn);

    // TODO: Actually handle errors
    if (error) {
        // delete conn;
    }

    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address())) {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
    }

    // start HTTP client thread
    else if (!NewThread(ThreadRPCServer3, conn)) {
        NLog.write(b_sev::err, "Failed to create RPC server client thread");
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
}

void ThreadRPCServer2()
{
    NLog.write(b_sev::info, "ThreadRPCServer started");

    if (!InitRPCAuthentication()) {
        StartShutdown();
        return;
    }

    const bool fUseSSL = false; // SSL disabled

    // this is made static due to issues of possible race conditions when shutting down
    // the issue is probably caused by trying to clear/read the queue after having deleted the acceptor,
    // where the RPC request is also deleted
    static asio::io_service io_service;
    io_service.reset();

#if ((BOOST_VERSION / 100000) > 1) && ((BOOST_VERSION / 100 % 1000) >= 47)
    ssl::context context(io_service, ssl::context::sslv23);
#else
    ssl::context context(ssl::context::sslv23);
#endif

    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    const bool        loopback = !mapArgs.exists("-rpcallowip");
    asio::ip::address bindAddress =
        loopback ? asio::ip::address_v6::loopback() : asio::ip::address_v6::any();
    ip::tcp::endpoint         endpoint(bindAddress, GetArg("-rpcport", BaseParams().RPCPort()));
    boost::system::error_code v6_only_error;
    boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(io_service));

    fRpcListening.store(false);

    std::string strerr;
    try {
        acceptor->open(endpoint.protocol());
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

        acceptor->bind(endpoint);
        acceptor->listen(socket_base::max_connections);

        RPCListen(acceptor, context, fUseSSL);
        // Cancel outstanding listen-requests for this acceptor when shutting down
        StopRPCRequests.get().connect(signals2::slot<void()>([acceptor]() {
                                          if (!StopRPCRequestsFlag.test_and_set()) {
                                              boost::system::error_code ec;
                                              acceptor->cancel(ec);
                                              acceptor->close(ec);
                                          }
                                      })
                                          .track(acceptor));

        fRpcListening.store(true);
    } catch (boost::system::system_error& e) {
        strerr =
            fmt::format(_("An error occurred while setting up the RPC port {} for listening on IPv6, "
                          "falling back to IPv4: {}"),
                        endpoint.port(), e.what());
    }

    try {
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        if (!fRpcListening.load() || loopback || v6_only_error) {
            bindAddress = loopback ? asio::ip::address_v4::loopback() : asio::ip::address_v4::any();
            endpoint.address(bindAddress);

            acceptor.reset(new ip::tcp::acceptor(io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor->bind(endpoint);
            acceptor->listen(socket_base::max_connections);

            RPCListen(acceptor, context, fUseSSL);
            // Cancel outstanding listen-requests for this acceptor when shutting down
            StopRPCRequests.get().connect(signals2::slot<void()>([acceptor]() {
                                              if (!StopRPCRequestsFlag.test_and_set()) {
                                                  boost::system::error_code ec;
                                                  acceptor->cancel(ec);
                                                  acceptor->close(ec);
                                              }
                                          })
                                              .track(acceptor));

            fRpcListening.store(true);
        }
    } catch (boost::system::system_error& e) {
        strerr = fmt::format(
            _("An error occurred while setting up the RPC port {} for listening on IPv4: {}"),
            endpoint.port(), e.what());
    }

    if (!fRpcListening.load()) {
        uiInterface.ThreadSafeMessageBox(strerr, _("Error"),
                                         CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (!fShutdown) {
        io_service.run_one();
    }
    vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRPCRequests.get()();
}

class JSONRequest
{
public:
    Value  id;
    string strMethod;
    Array  params;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

void JSONRequest::parse(const Value& valRequest)
{
    // Parse request
    if (valRequest.type() != obj_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const Object& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    Value valMethod = find_value(request, "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getwork" && strMethod != "getblocktemplate")
        NLog.write(b_sev::info, "ThreadRPCServer method={}", strMethod);

    // Parse params
    Value valParams = find_value(request, "params");
    if (valParams.type() == array_type)
        params = valParams.get_array();
    else if (valParams.type() == null_type)
        params = Array();
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    try {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result   = JSONRPCReplyObj(result, Value::null, jreq.id);
    } catch (Object& objError) {
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    } catch (std::exception& e) {
        rpc_result = JSONRPCReplyObj(Value::null, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

static string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

static CCriticalSection cs_THREAD_RPCHANDLER;

void ThreadRPCServer3(boost::shared_ptr<AcceptedConnection> conn)
{
    // Make this thread recognisable as the RPC handler
    RenameThread("neblio-rpchand");

    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]++;
    }

    bool fRun = true;
    while (true) {
        if (fShutdown || !fRun) {
            conn->close();
            {
                LOCK(cs_THREAD_RPCHANDLER);
                --vnThreadsRunning[THREAD_RPCHANDLER];
            }
            return;
        }
        map<string, string> mapHeaders;
        string              strRequest;

        ReadHTTP(conn->stream(), mapHeaders, strRequest);

        // Check authorization
        if (mapHeaders.count("authorization") == 0) {
            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (!HTTPAuthorized(mapHeaders)) {
            NLog.write(b_sev::err, "ThreadRPCServer incorrect password attempt from {}",
                       conn->peer_address_to_string());
            /* Deter brute-forcing short passwords.
               If this results in a DOS the user really
               shouldn't have their RPC port exposed.*/
            const std::string rpcPassword = mapArgs.get("-rpcpassword").value_or("");
            if (rpcPassword.size() < 20)
                MilliSleep(250);

            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (mapHeaders["connection"] == "close")
            fRun = false;

        JSONRequest jreq;
        try {
            // Parse request
            Value valRequest;
            if (!read_string(strRequest, valRequest))
                throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

            string strReply;

            // singleton request
            if (valRequest.type() == obj_type) {
                jreq.parse(valRequest);

                Value result = tableRPC.execute(jreq.strMethod, jreq.params);

                // Send reply
                strReply = JSONRPCReply(result, Value::null, jreq.id);

                // array of requests
            } else if (valRequest.type() == array_type)
                strReply = JSONRPCExecBatch(valRequest.get_array());
            else
                throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

            conn->stream() << HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        } catch (Object& objError) {
            ErrorReply(conn->stream(), objError, jreq.id);
            break;
        } catch (std::exception& e) {
            ErrorReply(conn->stream(), JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
            break;
        }
    }

    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]--;
    }
}

json_spirit::Value CRPCTable::execute(const std::string&        strMethod,
                                      const json_spirit::Array& params) const
{
    // Find method
    const CRPCCommand* pcmd = tableRPC[strMethod];
    if (!pcmd) {
        NLog.write(b_sev::info, "Method not found: {}", strMethod);
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (" + std::string(strMethod) + ")");
    }

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode") && !pcmd->okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    try {
        // Execute
        Value result;
        {
            if (pcmd->unlocked)
                result = pcmd->actor(params, false);
            else {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                result = pcmd->actor(params, false);
            }
        }
        return result;
    } catch (std::exception& e) {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

std::vector<string> CRPCTable::listCommands() const
{
    std::vector<std::string>                          commandList;
    typedef std::map<std::string, const CRPCCommand*> commandMap;

    std::transform(mapCommands.begin(), mapCommands.end(), std::back_inserter(commandList),
                   boost::bind(&commandMap::value_type::first, _1));
    return commandList;
}

Object CallRPC(const string& strMethod, const Array& params)
{
    std::string rpcUser     = mapArgs.get("-rpcuser").value_or("");
    std::string rpcPassword = mapArgs.get("-rpcpassword").value_or("");
    if (rpcUser == "" && rpcPassword == "")
        throw runtime_error(fmt::format(
            _("You must set rpcpassword=<password> in the configuration file:\n{}\n"
              "If the file does not exist, create it with owner-readable-only file permissions."),
            GetConfigFile().string()));

    // Connect to localhost
    bool             fUseSSL = GetBoolArg("-rpcssl");
    asio::io_service io_service;
#if ((BOOST_VERSION / 100000) > 1) && ((BOOST_VERSION / 100 % 1000) >= 47)
    ssl::context context(io_service, ssl::context::sslv23);
#else
    ssl::context context(ssl::context::sslv23);
#endif
    context.set_options(ssl::context::no_sslv2);
    asio::ssl::stream<asio::ip::tcp::socket>            sslStream(io_service, context);
    SSLIOStreamDevice<asio::ip::tcp>                    d(sslStream, fUseSSL);
    iostreams::stream<SSLIOStreamDevice<asio::ip::tcp>> stream(d);
    if (!d.connect(GetArg("-rpcconnect", "127.0.0.1"),
                   GetArg("-rpcport", itostr(BaseParams().RPCPort()))))
        throw runtime_error("couldn't connect to server");

    // HTTP basic authentication
    string              strUserPass64 = EncodeBase64(rpcUser + ":" + rpcPassword);
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    string strPost    = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    map<string, string> mapHeaders;
    string              strReply;
    int                 nStatus = ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND &&
             nStatus != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(fmt::format("server returned HTTP error {}", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}

template <typename T>
void ConvertTo(Value& value, bool fAllowNull = false)
{
    if (fAllowNull && value.type() == null_type)
        return;
    if (value.type() == str_type) {
        // reinterpret string as unquoted json value
        Value  value2;
        string strJSON = value.get_str();
        if (!read_string(strJSON, value2))
            throw runtime_error(string("Error parsing JSON:") + strJSON);
        ConvertTo<T>(value2, fAllowNull);
        value = value2;
    } else {
        value = value.get_value<T>();
    }
}

// Convert strings to command-specific RPC representation
Array RPCConvertValues(const std::string& strMethod, const std::vector<std::string>& strParams)
{
    Array params;
    BOOST_FOREACH (const std::string& param, strParams)
        params.push_back(param);

    int n = params.size();

    //
    // Special case non-string parameter types
    //
    if (strMethod == "generate" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "generate" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "stop" && n > 0)
        ConvertTo<bool>(params[0]);
    if (strMethod == "sendtoaddress" && n > 1)
        ConvertTo<double>(params[1]);
    if (strMethod == "sendntp1toaddress" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "sendntp1toaddress" && n > 4)
        ConvertTo<bool>(params[4]);
    if (strMethod == "settxfee" && n > 0)
        ConvertTo<double>(params[0]);
    if (strMethod == "getreceivedbyaddress" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "getreceivedbyaccount" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "listreceivedbyaddress" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "listreceivedbyaddress" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "listreceivedbyaccount" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "listreceivedbyaccount" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "getbalance" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "getntp1balances" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "getblock" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "getblock" && n > 2)
        ConvertTo<bool>(params[2]);
    if (strMethod == "getblock" && n > 3)
        ConvertTo<bool>(params[3]);
    if (strMethod == "gettransaction" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "getblockbynumber" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "getblockbynumber" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "getblockbynumber" && n > 2)
        ConvertTo<bool>(params[2]);
    if (strMethod == "getblockhash" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "move" && n > 2)
        ConvertTo<double>(params[2]);
    if (strMethod == "move" && n > 3)
        ConvertTo<int64_t>(params[3]);
    if (strMethod == "sendfrom" && n > 2)
        ConvertTo<double>(params[2]);
    if (strMethod == "sendfrom" && n > 3)
        ConvertTo<int64_t>(params[3]);
    if (strMethod == "listtransactions" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "listtransactions" && n > 2)
        ConvertTo<int64_t>(params[2]);
    if (strMethod == "listaccounts" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "walletpassphrase" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "walletpassphrase" && n > 2)
        ConvertTo<bool>(params[2]);
    if (strMethod == "getblocktemplate" && n > 0)
        ConvertTo<Object>(params[0]);
    if (strMethod == "listsinceblock" && n > 1)
        ConvertTo<int64_t>(params[1]);

    if (strMethod == "sendalert" && n > 2)
        ConvertTo<int64_t>(params[2]);
    if (strMethod == "sendalert" && n > 3)
        ConvertTo<int64_t>(params[3]);
    if (strMethod == "sendalert" && n > 4)
        ConvertTo<int64_t>(params[4]);
    if (strMethod == "sendalert" && n > 5)
        ConvertTo<int64_t>(params[5]);
    if (strMethod == "sendalert" && n > 6)
        ConvertTo<int64_t>(params[6]);

    if (strMethod == "sendmany" && n > 1)
        ConvertTo<Object>(params[1]);
    if (strMethod == "sendmany" && n > 2)
        ConvertTo<int64_t>(params[2]);
    if (strMethod == "reservebalance" && n > 0)
        ConvertTo<bool>(params[0]);
    if (strMethod == "reservebalance" && n > 1)
        ConvertTo<double>(params[1]);
    if (strMethod == "addmultisigaddress" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "addmultisigaddress" && n > 1)
        ConvertTo<Array>(params[1]);
    if (strMethod == "listunspent" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "listunspent" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "listunspent" && n > 2)
        ConvertTo<Array>(params[2]);
    if (strMethod == "decoderawtransaction" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "getrawtransaction" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "getrawtransaction" && n > 2)
        ConvertTo<bool>(params[2]);
    if (strMethod == "createrawtransaction" && n > 0)
        ConvertTo<Array>(params[0]);
    if (strMethod == "createrawtransaction" && n > 1) {
        // it can be either an array or an object
        try {
            ConvertTo<Object>(params[1]);
        } catch (const std::exception& ex) {
            ConvertTo<Array>(params[1]);
        }
    }
    if (strMethod == "createrawntp1transaction" && n > 0)
        ConvertTo<Array>(params[0]);
    if (strMethod == "createrawntp1transaction" && n > 1) {
        // it can be either an array or an object
        try {
            ConvertTo<Object>(params[1]);
        } catch (const std::exception& ex) {
            ConvertTo<Array>(params[1]);
        }
    }
    if (strMethod == "createrawntp1transaction" && n > 3)
        ConvertTo<bool>(params[3]);
    if (strMethod == "signrawtransaction" && n > 1)
        ConvertTo<Array>(params[1], true);
    if (strMethod == "signrawtransaction" && n > 2)
        ConvertTo<Array>(params[2], true);
    if (strMethod == "keypoolrefill" && n > 0)
        ConvertTo<int64_t>(params[0]);
    if (strMethod == "generateblockwithkey" && n > 1)
        ConvertTo<int64_t>(params[1]);
    if (strMethod == "generateblockwithkey" && n > 3)
        ConvertTo<Array>(params[3]);
    if (strMethod == "generateblockwithkey" && n > 4)
        ConvertTo<int64_t>(params[4]);
    if (strMethod == "listcoldutxos" && n > 0)
        ConvertTo<bool>(params[0]);
    if (strMethod == "listdelegators" && n > 0)
        ConvertTo<bool>(params[0]);
    if (strMethod == "delegatestake" && n > 1)
        ConvertTo<double>(params[1]);
    if (strMethod == "delegatestake" && n > 3)
        ConvertTo<bool>(params[3]);
    if (strMethod == "delegatestake" && n > 4)
        ConvertTo<bool>(params[4]);
    if (strMethod == "delegatestake" && n > 5)
        ConvertTo<bool>(params[5]);
    if (strMethod == "rawdelegatestake" && n > 1)
        ConvertTo<double>(params[1]);
    if (strMethod == "rawdelegatestake" && n > 3)
        ConvertTo<bool>(params[3]);
    if (strMethod == "rawdelegatestake" && n > 4)
        ConvertTo<bool>(params[4]);
    if (strMethod == "castvote" && n > 0)
        ConvertTo<int>(params[0]);
    if (strMethod == "castvote" && n > 1)
        ConvertTo<int>(params[1]);
    if (strMethod == "castvote" && n > 2)
        ConvertTo<int>(params[2]);
    if (strMethod == "castvote" && n > 3)
        ConvertTo<int>(params[3]);
    if (strMethod == "cancelallvotesofproposal" && n > 0)
        ConvertTo<int>(params[0]);
    if (strMethod == "addledgeraddress" && n > 0)
        ConvertTo<int>(params[0]);
    if (strMethod == "addledgeraddress" && n > 1)
        ConvertTo<int>(params[1]);
    if (strMethod == "verifyledgeraddress" && n > 0)
        ConvertTo<int>(params[0]);
    if (strMethod == "verifyledgeraddress" && n > 1)
        ConvertTo<bool>(params[1]);
    if (strMethod == "verifyledgeraddress" && n > 2)
        ConvertTo<int>(params[2]);
    if (strMethod == "generatetoaddress" && n > 0)
        ConvertTo<int>(params[0]);
    if (strMethod == "generatetoaddress" && n > 2)
        ConvertTo<int>(params[2]);

    return params;
}

int CommandLineRPC(int argc, char* argv[])
{
    string strPrint;
    int    nRet = 0;
    try {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0])) {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]);
        Array                    params = RPCConvertValues(strMethod, strParams);

        // Execute
        Object reply = CallRPC(strMethod, params);

        // Parse reply
        const Value& result = find_value(reply, "result");
        const Value& error  = find_value(reply, "error");

        if (error.type() != null_type) {
            // Error
            strPrint = "error: " + write_string(error, false);
            int code = find_value(error.get_obj(), "code").get_int();
            nRet     = abs(code);
        } else {
            // Result
            if (result.type() == null_type)
                strPrint = "";
            else if (result.type() == str_type)
                strPrint = result.get_str();
            else
                strPrint = write_string(result, true);
        }
    } catch (std::exception& e) {
        strPrint = string("error: ") + e.what();
        nRet     = 87;
    } catch (...) {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "") {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}

#ifdef TEST
int main(int argc, char* argv[])
{
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try {
        if (argc >= 2 && string(argv[1]) == "-server") {
            NLog.write(b_sev::info, "server ready");
            ThreadRPCServer(NULL);
        } else {
            return CommandLineRPC(argc, argv);
        }
    } catch (std::exception& e) {
        PrintException(&e, "main()");
    } catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif

const CRPCTable tableRPC;

std::string GetTokenIDFromTokenName(const std::string& tokenName)
{
    CTxDB                txdb;
    std::vector<uint256> ntp1IssuanceTxHashes;
    if (!txdb.ReadNTP1TxsWithTokenSymbol(tokenName, ntp1IssuanceTxHashes)) {
        throw std::runtime_error("An NTP1 token name was (at least an invalid token "
                                 "ID), but it wasn't found in the blockchain: " +
                                 tokenName);
    }
    // ensure token issuance was done in main chain
    boost::optional<uint256> issuanceTxInMainChain;
    for (const uint256& hash : ntp1IssuanceTxHashes) {
        CTxIndex txindex;
        if (txdb.ReadTxIndex(hash, txindex)) {
            issuanceTxInMainChain = hash;
            break;
        }
    }
    if (!issuanceTxInMainChain) {
        throw std::runtime_error("The token name given " + tokenName +
                                 " was not found in any transaction that issued it");
    }

    // get the NTP1Transaction object
    const CTransaction tx     = CTransaction::FetchTxFromDisk(*issuanceTxInMainChain, txdb);
    auto               txPair = std::make_pair(tx, NTP1Transaction());
    FetchNTP1TxFromDisk(txPair, txdb, false);

    // extract token ID
    const auto&       prevout0 = txPair.first.vin[0].prevout;
    const std::string tokenId = txPair.second.getTokenIdIfIssuance(prevout0.hash.ToString(), prevout0.n);
    return tokenId;
}

NTP1SendTokensOneRecipientData ParseRPCNTP1OutputJson(const json_spirit::Pair&             s,
                                                      const boost::shared_ptr<NTP1Wallet>& ntp1wallet,
                                                      bool getDataStrictlyFromNTP1Wallet)
{
    NTP1SendTokensOneRecipientData res;
    if (s.value_.type() == json_spirit::Value_type::obj_type) {
        // NTP1 token (since the json type is object)
        json_spirit::Object obj = s.value_.get_obj();
        if (obj.size() != 1) {
            throw std::runtime_error("Invalid tokenId and amount pair.");
        }
        NTP1Int nAmount = NTP1AmountFromValue(obj[0].value_);
        if (nAmount <= 0) {
            throw std::runtime_error("Invalid amount: " + ::ToString(res.amount));
        }
        res.amount                   = static_cast<uint64_t>(nAmount);
        const std::string providedId = obj[0].name_;

        const std::unordered_map<std::string, NTP1TokenMetaData> tokenMetadataMap =
            ntp1wallet->getTokenMetadataMap();
        // token id was not found
        if (getDataStrictlyFromNTP1Wallet &&
            tokenMetadataMap.find(providedId) == tokenMetadataMap.end()) {
            res.tokenId   = "";
            int nameCount = 0; // number of tokens that have that name
            // try to find whether the name of the token matches with what's provided
            for (const auto& tokenMetadata : tokenMetadataMap) {
                if (tokenMetadata.second.getTokenName() == providedId) {
                    res.tokenId = tokenMetadata.second.getTokenId();
                    nameCount++;
                }
            }
            if (res.tokenId == "") {
                throw std::runtime_error("Failed to find token by the id/name: " + providedId);
            }
            if (nameCount > 1) {
                throw std::runtime_error("Found multiple tokens by the name " + providedId);
            }
        } else {
            std::vector<unsigned char> decoded;
            if (!DecodeBase58Check(providedId, decoded)) {
                // this is a token given by name, not by ID
                res.tokenId = GetTokenIDFromTokenName(providedId);
            } else {
                // this is a token given by ID, not by name
                res.tokenId = providedId;
            }
        }
    } else {
        // nebls
        CAmount nAmount = AmountFromValue(s.value_);
        res.amount      = static_cast<uint64_t>(nAmount);
        if (nAmount <= 0) {
            throw std::runtime_error("Invalid amount: " + ::ToString(res.amount));
        }
        res.tokenId = NTP1SendTxData::NEBL_TOKEN_ID;
    }
    return res;
}

std::vector<NTP1SendTokensOneRecipientData>
GetNTP1RecipientsVector(const Value& sendToVal, boost::shared_ptr<NTP1Wallet> ntp1wallet,
                        bool getDataStrictlyFromNTP1Wallet)
{
    std::vector<NTP1SendTokensOneRecipientData> result;
    if (sendToVal.type() == Value_type::obj_type) {
        for (const json_spirit::Pair& s : sendToVal.get_obj()) {
            set<CBitcoinAddress> setAddress;
            CBitcoinAddress      address(s.name_);
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   string("Invalid neblio address: ") + s.name_);

            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   string("Invalid parameter, duplicated address: ") + s.name_);
            setAddress.insert(address);

            CScript scriptPubKey;
            scriptPubKey.SetDestination(address.Get());

            NTP1SendTokensOneRecipientData res =
                ParseRPCNTP1OutputJson(s, ntp1wallet, getDataStrictlyFromNTP1Wallet);
            res.destination = address.ToString();
            result.push_back(res);
        }
    } else if (sendToVal.type() == Value_type::array_type) {
        const Array sendTo = sendToVal.get_array();
        for (long i = 0; i < static_cast<long>(sendTo.size()); i++) {
            if (sendTo[i].type() != Value_type::obj_type) {
                throw JSONRPCError(
                    RPC_TYPE_ERROR,
                    string("Invalid parameter type in the destination array; element number " +
                           std::to_string(i) + " (starting from 0) is not an object"));
            }
            const Object addressObj = sendTo[i].get_obj();
            if (addressObj.size() != 1) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    string("Invalid parameter in the destination array; element number " +
                           std::to_string(i) +
                           " (starting from 0) is an object that contains more than one element"));
            }
            const Pair            s = addressObj.front();
            const CBitcoinAddress address(s.name_);

            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   string("Invalid neblio address: ") + s.name_);

            NTP1SendTokensOneRecipientData res =
                ParseRPCNTP1OutputJson(s, ntp1wallet, getDataStrictlyFromNTP1Wallet);
            res.destination = address.ToString();
            result.push_back(res);
        }
    } else {
        throw JSONRPCError(
            RPC_TYPE_ERROR,
            "Invalid parameter type for destination; it can be either an object or an array "
            "of objects; please refer to the examples.");
    }
    return result;
}

bool IsRPCRunning() { return fRpcListening.load(); }
