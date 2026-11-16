// PRiVY all-in-one C++17 backend: HTTP server, authentication, SQLite APIs, and phishing detection.
// Frontend files are served as static assets; no Node.js/Express backend is required.
// Windows Winsock2 port: replaces POSIX sockets and crypt(3) with OpenSSL PBKDF2-SHA256.
#include "PhishingDetector.h"
#include "ScanResult.h"
#include "sqlite3.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <cmath>
#include <fstream>

// ---- Windows networking ----
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
   // ssize_t is defined in corecrt.h on MSYS2/MinGW as __int64; no redefinition needed.
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif

namespace {
struct Request { std::string method, path, body, auth; };
struct User { int id=0; std::string username,email,role,createdAt; };
std::string dbPath="privy.db", jwtSecret="privy-production-super-secret-jwt-key-2026", adminKey="privy-admin-secret-2026", adminPassword="Admin@12345", publicDir="public";
sqlite3* db=nullptr;

// ---- Platform socket helpers ----
inline void closeSocket(int fd) {
#ifdef _WIN32
    closesocket((SOCKET)fd);
#else
    close(fd);
#endif
}

// ---- String utilities ----
std::string trim(std::string s){ auto b=s.find_first_not_of(" \t\r\n"); if(b==std::string::npos)return ""; auto e=s.find_last_not_of(" \t\r\n"); return s.substr(b,e-b+1); }
std::string jsonEscape(const std::string& v){std::ostringstream o;for(unsigned char c:v){switch(c){case '"':o<<"\\\"";break;case '\\':o<<"\\\\";break;case '\n':o<<"\\n";break;case '\r':o<<"\\r";break;case '\t':o<<"\\t";break;default:if(c<32)o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)c<<std::dec;else o<<(char)c;}}return o.str();}
std::string js(const std::string& v){return "\""+jsonEscape(v)+"\"";}
bool jsonString(const std::string& s,const std::string& key,std::string& out){std::string needle="\""+key+"\"";auto p=s.find(needle);if(p==std::string::npos)return false;p=s.find(':',p+needle.size());if(p==std::string::npos)return false;++p;while(p<s.size()&&std::isspace((unsigned char)s[p]))++p;if(p>=s.size()||s[p]!='"')return false;++p;out.clear();while(p<s.size()){char c=s[p++];if(c=='"')return true;if(c=='\\'&&p<s.size()){char e=s[p++];switch(e){case 'n':out+='\n';break;case 'r':out+='\r';break;case 't':out+='\t';break;case 'b':out+='\b';break;case 'f':out+='\f';break;default:out+=e;}}else out+=c;}return false;}
std::string field(const std::string&s,const std::string&k,const std::string&def=""){std::string v;return jsonString(s,k,v)?v:def;}
std::string rawValue(const std::string&s,const std::string&k,const std::string&def=""){auto p=s.find("\""+k+"\"");if(p==std::string::npos)return def;p=s.find(':',p);if(p==std::string::npos)return def;++p;while(p<s.size()&&std::isspace((unsigned char)s[p]))++p;auto e=p; if(e<s.size()&&s[e]=='"'){++e;bool esc=false;while(e<s.size()){if(!esc&&s[e]=='"')break;if(!esc&&s[e]=='\\')esc=true;else esc=false;++e;}return s.substr(p,e-p+1);}while(e<s.size()&&s[e]!=','&&s[e]!='}'&& !std::isspace((unsigned char)s[e]))++e;return s.substr(p,e-p);}
bool endsWith(const std::string&s,const std::string&suffix){return s.size()>=suffix.size()&&s.compare(s.size()-suffix.size(),suffix.size(),suffix)==0;}
std::string urlDecode(std::string s){std::string out;for(size_t i=0;i<s.size();++i){if(s[i]=='+')out+=' ';else if(s[i]=='%'&&i+2<s.size()){char h[3]={s[i+1],s[i+2],0};char* end=nullptr;long v=std::strtol(h,&end,16);if(end&&*end==0){out+=(char)v;i+=2;}else out+=s[i];}else out+=s[i];}return out;}
std::string query(const std::string& path,const std::string& key){auto q=path.find('?');if(q==std::string::npos)return "";std::string s=path.substr(q+1),n=key+"=";auto p=s.find(n);if(p==std::string::npos)return "";p+=n.size();auto e=s.find('&',p);return urlDecode(s.substr(p,e==std::string::npos?e:e-p));}
std::string routePath(const std::string& p){auto q=p.find('?');return q==std::string::npos?p:p.substr(0,q);}

// ---- Base64url for JWT ----
std::string b64url(const unsigned char* data,size_t len){std::string out(4*((len+2)/3),'\0');int n=EVP_EncodeBlock((unsigned char*)out.data(),data,(int)len);out.resize(n);for(char&c:out){if(c=='+')c='-';else if(c=='/')c='_';}while(!out.empty()&&out.back()=='=')out.pop_back();return out;}
std::string b64decode(std::string s){for(char&c:s){if(c=='-')c='+';else if(c=='_')c='/';}while(s.size()%4)s+='=';std::string out((s.size()*3)/4,'\0');int n=EVP_DecodeBlock((unsigned char*)out.data(),(const unsigned char*)s.data(),(int)s.size());if(n<0)return "";while(!s.empty()&&s.back()=='='){--n;s.pop_back();}out.resize(std::max(0,n));return out;}
std::string hmac256(const std::string& data){unsigned char digest[EVP_MAX_MD_SIZE];unsigned int len=0;HMAC(EVP_sha256(),jwtSecret.data(),(int)jwtSecret.size(),(const unsigned char*)data.data(),data.size(),digest,&len);return b64url(digest,len);}
std::string makeToken(const User& u){long exp=(long)std::time(nullptr)+12*60*60;std::string head=b64url((const unsigned char*)"{\"alg\":\"HS256\",\"typ\":\"JWT\"}",27);std::string payload="{\"id\":"+std::to_string(u.id)+",\"username\":"+js(u.username)+",\"email\":"+js(u.email)+",\"role\":"+js(u.role)+",\"exp\":"+std::to_string(exp)+"}";std::string p=b64url((const unsigned char*)payload.data(),payload.size());std::string data=head+"."+p;return data+"."+hmac256(data);}
bool tokenUser(const std::string& token,User& u){auto a=token.find('.'),b=token.find('.',a==std::string::npos?a:a+1);if(a==std::string::npos||b==std::string::npos)return false;std::string data=token.substr(0,b),sig=token.substr(b+1);if(hmac256(data)!=sig)return false;std::string payload=b64decode(token.substr(a+1,b-a-1));std::string id=field(payload,"id");
 auto p=payload.find("\"id\":");if(p==std::string::npos)return false;p+=5;while(p<payload.size()&&std::isspace((unsigned char)payload[p]))p++;u.id=std::atoi(payload.c_str()+p);u.username=field(payload,"username");u.email=field(payload,"email");u.role=field(payload,"role");auto ep=payload.find("\"exp\":");if(ep!=std::string::npos){ep+=6;long ex=std::atol(payload.c_str()+ep);if(ex<(long)std::time(nullptr))return false;}return u.id>0&&!u.username.empty()&&(u.role=="user"||u.role=="admin");}

// ---- Password hashing: PBKDF2-SHA256 (cross-platform, OpenSSL) ----
// Format: "$pbkdf2$<hex-salt>$<hex-hash>" — 32 bytes salt, 32 bytes key, 100000 iterations
static const int PBKDF2_ITERS = 100000;
static const int SALT_LEN = 32;
static const int KEY_LEN  = 32;

static std::string bytesToHex(const unsigned char* b, int len) {
    std::ostringstream o;
    for(int i=0;i<len;i++) o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b[i];
    return o.str();
}

static bool hexToBytes(const std::string& hex, unsigned char* out, int expected) {
    if((int)hex.size() != expected*2) return false;
    for(int i=0;i<expected;i++){
        char h[3]={hex[2*i],hex[2*i+1],0};
        char* end=nullptr;
        out[i]=(unsigned char)std::strtol(h,&end,16);
        if(!end||*end) return false;
    }
    return true;
}

std::string hashPassword(const std::string& password) {
    unsigned char salt[SALT_LEN];
    if(RAND_bytes(salt, SALT_LEN) != 1) return "";
    unsigned char key[KEY_LEN];
    if(PKCS5_PBKDF2_HMAC(password.c_str(),(int)password.size(),salt,SALT_LEN,PBKDF2_ITERS,EVP_sha256(),KEY_LEN,key) != 1) return "";
    return "$pbkdf2$" + bytesToHex(salt,SALT_LEN) + "$" + bytesToHex(key,KEY_LEN);
}

bool verifyPassword(const std::string& password, const std::string& stored) {
    if(stored.rfind("$pbkdf2$",0) != 0) {
        // Legacy bcrypt hash from previous Linux build — cannot verify on Windows.
        // If this is the seeded admin, it will be re-seeded on first run with a fresh db.
        return false;
    }
    // Parse "$pbkdf2$<salt-hex>$<key-hex>"
    auto p1 = stored.find('$', 8); // after "$pbkdf2$"
    if(p1 == std::string::npos) return false;
    std::string saltHex = stored.substr(8, p1-8);
    std::string keyHex  = stored.substr(p1+1);
    unsigned char salt[SALT_LEN], expected[KEY_LEN], actual[KEY_LEN];
    if(!hexToBytes(saltHex, salt, SALT_LEN)) return false;
    if(!hexToBytes(keyHex,  expected, KEY_LEN)) return false;
    if(PKCS5_PBKDF2_HMAC(password.c_str(),(int)password.size(),salt,SALT_LEN,PBKDF2_ITERS,EVP_sha256(),KEY_LEN,actual) != 1) return false;
    // Constant-time compare
    return CRYPTO_memcmp(actual, expected, KEY_LEN) == 0;
}

// ---- SQLite helpers ----
void execSql(const char* sql){char* e=nullptr;if(sqlite3_exec(db,sql,nullptr,nullptr,&e)!=SQLITE_OK){std::cerr<<"SQLite: "<<(e?e:"unknown")<<"\n";sqlite3_free(e);}}
int run(const char* sql,const std::vector<std::string>& vals={},sqlite3_int64* last=nullptr){sqlite3_stmt* st=nullptr;if(sqlite3_prepare_v2(db,sql,-1,&st,nullptr)!=SQLITE_OK)return -1;for(size_t i=0;i<vals.size();++i)sqlite3_bind_text(st,(int)i+1,vals[i].c_str(),-1,SQLITE_TRANSIENT);int rc=sqlite3_step(st);int changes=sqlite3_changes(db);if(last)*last=sqlite3_last_insert_rowid(db);sqlite3_finalize(st);return rc==SQLITE_DONE?changes:-1;}
std::string col(sqlite3_stmt* st,int i){const unsigned char* p=sqlite3_column_text(st,i);return p?(const char*)p:"";}

void initDb(){
    execSql("PRAGMA foreign_keys=ON");
    execSql("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,email TEXT,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('user','admin')),created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    execSql("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,url TEXT NOT NULL,is_phishing INTEGER DEFAULT 0,security_score INTEGER DEFAULT 100,result TEXT NOT NULL,timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");
    // Check if admin exists and has a valid (pbkdf2) hash; re-seed if necessary
    sqlite3_stmt* st=nullptr;
    bool needReseed=true;
    sqlite3_prepare_v2(db,"SELECT id,password_hash FROM users WHERE role='admin' LIMIT 1",-1,&st,nullptr);
    if(sqlite3_step(st)==SQLITE_ROW){
        std::string h=col(st,1);
        // If the stored hash is already pbkdf2, admin is fine
        if(h.rfind("$pbkdf2$",0)==0) needReseed=false;
        else {
            // Legacy bcrypt hash — update it
            int adminId=sqlite3_column_int(st,0);
            sqlite3_finalize(st); st=nullptr;
            auto nh=hashPassword(adminPassword);
            if(!nh.empty()) run("UPDATE users SET password_hash=? WHERE id=?",{nh,std::to_string(adminId)});
            std::cout<<"[DB] Admin password hash migrated to PBKDF2-SHA256\n";
            needReseed=false;
        }
    }
    if(st) sqlite3_finalize(st);
    if(needReseed){
        auto h=hashPassword(adminPassword);
        if(!h.empty()) run("INSERT INTO users(username,email,password_hash,role) VALUES('admin','admin@privy.local',?,'admin')",{h});
        std::cout<<"[DB] Default administrator seeded (admin / configured password)\n";
    }
}

User getUser(int id){User u;sqlite3_stmt* st=nullptr;if(sqlite3_prepare_v2(db,"SELECT id,username,COALESCE(email,''),role,created_at FROM users WHERE id=?",-1,&st,nullptr)==SQLITE_OK){sqlite3_bind_int(st,1,id);if(sqlite3_step(st)==SQLITE_ROW){u.id=sqlite3_column_int(st,0);u.username=col(st,1);u.email=col(st,2);u.role=col(st,3);u.createdAt=col(st,4);}sqlite3_finalize(st);}return u;}

// ---- HTTP helpers ----
std::string responseJson(int status,const std::string& body,const std::string& contentType="application/json; charset=utf-8"){return "HTTP/1.1 "+std::to_string(status)+" "+(status==200?"OK":status==201?"Created":status==204?"No Content":status==400?"Bad Request":status==401?"Unauthorized":status==403?"Forbidden":status==404?"Not Found":status==409?"Conflict":"Internal Server Error")+"\r\nContent-Type: "+contentType+"\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nAccess-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS\r\nConnection: close\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n"+body;}

void sendAll(int fd,const std::string& bytes){
    size_t sent=0;
    while(sent<bytes.size()){
#ifdef _WIN32
        int n=send((SOCKET)fd,bytes.data()+(int)sent,(int)(bytes.size()-sent),0);
#else
        ssize_t n=send(fd,bytes.data()+sent,bytes.size()-sent,0);
#endif
        if(n<=0)break;
        sent+=(size_t)n;
    }
}

std::string reasons(const std::string& raw){auto p=raw.find("\"reasons\"");if(p==std::string::npos)return "[]";p=raw.find('[',p);if(p==std::string::npos)return "[]";int d=0;bool in=false,esc=false;for(size_t i=p;i<raw.size();i++){char c=raw[i];if(in){if(esc)esc=false;else if(c=='\\')esc=true;else if(c=='"')in=false;}else if(c=='"')in=true;else if(c=='[')d++;else if(c==']'&&--d==0)return raw.substr(p,i-p+1);}return "[]";}
std::string scanRow(sqlite3_stmt* st,bool admin){std::string out="{\"id\":"+std::to_string(sqlite3_column_int(st,0));int base=admin?2:1;if(admin)out+=",\"username\":"+js(col(st,1));out+=",\"url\":"+js(col(st,base))+",\"isPhishing\":"+(sqlite3_column_int(st,base+1)?"true":"false")+",\"securityScore\":"+std::to_string(sqlite3_column_int(st,base+2))+",\"reasons\":"+reasons(col(st,base+3))+",\"timestamp\":"+js(col(st,base+4))+"}";return out;}
std::string history(int uid){sqlite3_stmt*st=nullptr;std::string out="[";bool first=true;if(sqlite3_prepare_v2(db,"SELECT id,url,is_phishing,security_score,result,timestamp FROM scans WHERE user_id=? ORDER BY timestamp DESC",-1,&st,nullptr)==SQLITE_OK){sqlite3_bind_int(st,1,uid);while(sqlite3_step(st)==SQLITE_ROW){if(!first)out+=",";first=false;out+=scanRow(st,false);}sqlite3_finalize(st);}return out+"]";}
std::string adminStats(){auto count=[](const char* q){sqlite3_stmt*s=nullptr;int n=0;if(sqlite3_prepare_v2(db,q,-1,&s,nullptr)==SQLITE_OK&&sqlite3_step(s)==SQLITE_ROW)n=sqlite3_column_int(s,0);if(s)sqlite3_finalize(s);return n;};int users=count("SELECT COUNT(*) FROM users"),scans=count("SELECT COUNT(*) FROM scans"),safe=count("SELECT COUNT(*) FROM scans WHERE is_phishing=0"),phish=count("SELECT COUNT(*) FROM scans WHERE is_phishing=1");double avg=100;if(scans){sqlite3_stmt*s=nullptr;if(sqlite3_prepare_v2(db,"SELECT AVG(security_score) FROM scans",-1,&s,nullptr)==SQLITE_OK&&sqlite3_step(s)==SQLITE_ROW)avg=sqlite3_column_double(s,0);if(s)sqlite3_finalize(s);}std::ostringstream a;a<<std::fixed<<std::setprecision(1)<<avg;std::string recent="[";bool f=true;sqlite3_stmt*s=nullptr;if(sqlite3_prepare_v2(db,"SELECT s.id,u.username,s.url,s.is_phishing,s.security_score,s.result,s.timestamp FROM scans s JOIN users u ON s.user_id=u.id ORDER BY s.timestamp DESC LIMIT 8",-1,&s,nullptr)==SQLITE_OK){while(sqlite3_step(s)==SQLITE_ROW){if(!f)recent+=",";f=false;recent+="{\"id\":"+std::to_string(sqlite3_column_int(s,0))+",\"username\":"+js(col(s,1))+",\"url\":"+js(col(s,2))+",\"isPhishing\":"+(sqlite3_column_int(s,3)?"true":"false")+",\"securityScore\":"+std::to_string(sqlite3_column_int(s,4))+",\"reasons\":"+reasons(col(s,5))+",\"timestamp\":"+js(col(s,6))+"}";}sqlite3_finalize(s);}recent+="]";int safePct=scans?(int)std::round((double)safe/scans*100):100,phPct=scans?(int)std::round((double)phish/scans*100):0;return "{\"totalUsers\":"+std::to_string(users)+",\"totalScans\":"+std::to_string(scans)+",\"safeScans\":"+std::to_string(safe)+",\"phishingScans\":"+std::to_string(phish)+",\"safePercentage\":"+std::to_string(safePct)+",\"phishingPercentage\":"+std::to_string(phPct)+",\"averageSecurityScore\":"+a.str()+",\"recentScans\":"+recent+"}";}
std::string error(int code,const std::string& msg){return responseJson(code,"{\"error\":"+js(msg)+"}");}

// ---- Request router ----
std::string handle(const Request&r){std::string p=routePath(r.path),body=r.body;User u;bool logged=false;if(!r.auth.empty()){auto sp=r.auth.find(' ');if(sp!=std::string::npos&&r.auth.substr(0,sp)=="Bearer")logged=tokenUser(r.auth.substr(sp+1),u);}auto needAuth=[&](){return logged?std::string():error(401,"Access denied: Authentication token required");};auto needAdmin=[&](){if(!logged)return error(401,"Access denied: Authentication token required");if(u.role!="admin")return error(403,"Forbidden: Insufficient administrative privileges");return std::string();};
 if(r.method=="OPTIONS")return responseJson(204,"");
 if(r.method=="GET"&&p=="/api/health")return responseJson(200,"{\"status\":\"ok\",\"engine\":\"PRiVY C++ Full Backend\"}");
 if(r.method=="POST"&&p=="/api/register"){std::string username=trim(field(body,"username")),email=trim(field(body,"email")),password=field(body,"password"),role=field(body,"role"),key=trim(field(body,"adminKey"));if(username.empty()||password.empty())return error(400,"Username and password are required");if(username.size()<3||username.size()>30)return error(400,"Username must be between 3 and 30 characters");if(password.size()<6)return error(400,"Password must be at least 6 characters long");std::string assigned="user";if(role=="admin"){if(key!=adminKey)return error(403,"Unauthorized: Invalid Admin Registration Key. Normal users cannot register as Admin.");assigned="admin";}sqlite3_stmt*s=nullptr;sqlite3_prepare_v2(db,"SELECT id FROM users WHERE username=? OR (?<>'' AND email=?) LIMIT 1",-1,&s,nullptr);sqlite3_bind_text(s,1,username.c_str(),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,email.c_str(),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,3,email.c_str(),-1,SQLITE_TRANSIENT);bool exists=sqlite3_step(s)==SQLITE_ROW;sqlite3_finalize(s);if(exists)return error(409,"Username or email address is already registered.");auto h=hashPassword(password);if(h.empty())return error(500,"Password hashing failed");sqlite3_int64 id=0;if(run("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",{username,email,h,assigned},&id)<0)return error(500,"Internal server error during registration");User nu;nu.id=(int)id;nu.username=username;nu.email=email;nu.role=assigned;return responseJson(201,"{\"message\":\"Account created successfully\",\"token\":"+js(makeToken(nu))+",\"role\":"+js(assigned)+",\"user\":{\"id\":"+std::to_string(id)+",\"username\":"+js(username)+",\"email\":"+js(email)+",\"role\":"+js(assigned)+"}}") ;}
 if(r.method=="POST"&&p=="/api/login"){std::string ident=trim(field(body,"username")),password=field(body,"password");if(ident.empty()||password.empty())return error(400,"Username/Email and password are required");sqlite3_stmt*s=nullptr;sqlite3_prepare_v2(db,"SELECT id,username,COALESCE(email,''),password_hash,role FROM users WHERE username=? OR email=? LIMIT 1",-1,&s,nullptr);sqlite3_bind_text(s,1,ident.c_str(),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,ident.c_str(),-1,SQLITE_TRANSIENT);if(sqlite3_step(s)!=SQLITE_ROW){sqlite3_finalize(s);return error(401,"Invalid username or password");}User nu;nu.id=sqlite3_column_int(s,0);nu.username=col(s,1);nu.email=col(s,2);std::string h=col(s,3);nu.role=col(s,4);sqlite3_finalize(s);if(!verifyPassword(password,h))return error(401,"Invalid username or password");return responseJson(200,"{\"message\":\"Authentication successful\",\"token\":"+js(makeToken(nu))+",\"role\":"+js(nu.role)+",\"user\":{\"id\":"+std::to_string(nu.id)+",\"username\":"+js(nu.username)+",\"email\":"+js(nu.email)+",\"role\":"+js(nu.role)+"}}") ;}
 if(r.method=="GET"&&p=="/api/me"){auto e=needAuth();if(!e.empty())return e;User current=getUser(u.id);if(!current.id)return error(404,"User account not found");return responseJson(200,"{\"user\":{\"id\":"+std::to_string(current.id)+",\"username\":"+js(current.username)+",\"email\":"+js(current.email)+",\"role\":"+js(current.role)+",\"created_at\":"+js(current.createdAt)+"}}") ;}
 if(r.method=="POST"&&(p=="/api/scan"||p=="/api/analyze"||p=="/api/detect")){if(p=="/api/scan"){auto e=needAuth();if(!e.empty())return e;}std::string url=trim(field(body,"url"));if(url.empty())return error(400,"Valid URL is required for scanning");PhishingDetector d(url);ScanResult result=d.detect();std::string res=result.toJson();bool isPh=rawValue(res,"isPhishing")=="true";std::string score=rawValue(res,"securityScore","100");if(p=="/api/scan"||(p=="/api/analyze"&&logged)){sqlite3_int64 sid=0;if(run("INSERT INTO scans(user_id,url,is_phishing,security_score,result) VALUES(?,?,?,?,?)",{std::to_string(u.id),url,isPh?"1":"0",score,res},&sid)<0)return error(500,"Failed to save scan history");if(p=="/api/scan"){std::time_t now=std::time(nullptr);std::tm tmv=*std::gmtime(&now);char ts[32];std::strftime(ts,sizeof(ts),"%Y-%m-%dT%H:%M:%S.000Z",&tmv);return responseJson(200,res.substr(0,res.size()-1)+",\"scanId\":"+std::to_string(sid)+",\"timestamp\":"+js(ts)+"}") ;}}return responseJson(200,res);}
 if(r.method=="GET"&&p=="/api/history"){auto e=needAuth();if(!e.empty())return e;return responseJson(200,history(u.id));}
 if(r.method=="DELETE"&&p=="/api/history"){auto e=needAuth();if(!e.empty())return e;int n=run("DELETE FROM scans WHERE user_id=?",{std::to_string(u.id)});return responseJson(200,"{\"message\":\"Scan history cleared successfully\",\"deletedCount\":"+std::to_string(std::max(0,n))+"}");}
 if(r.method=="DELETE"&&p.rfind("/api/history/",0)==0){auto e=needAuth();if(!e.empty())return e;int sid=std::atoi(p.substr(std::string("/api/history/").size()).c_str());if(sid<=0)return error(400,"Invalid scan ID");int n=run("DELETE FROM scans WHERE id=? AND user_id=?",{std::to_string(sid),std::to_string(u.id)});return n?responseJson(200,"{\"message\":\"Scan record deleted successfully\"}"):error(404,"Scan record not found or unauthorized");}
 if(r.method=="GET"&&p=="/api/admin/stats"){auto e=needAdmin();if(!e.empty())return e;return responseJson(200,adminStats());}
 if(r.method=="GET"&&p=="/api/admin/users"){auto e=needAdmin();if(!e.empty())return e;std::string search=trim(query(r.path,"search"));sqlite3_stmt*s=nullptr;std::string sql="SELECT u.id,u.username,COALESCE(u.email,''),u.role,u.created_at,COUNT(sc.id) FROM users u LEFT JOIN scans sc ON u.id=sc.user_id";if(!search.empty())sql+=" WHERE u.username LIKE ? OR u.email LIKE ?";sql+=" GROUP BY u.id ORDER BY u.id ASC";sqlite3_prepare_v2(db,sql.c_str(),-1,&s,nullptr);if(!search.empty()){std::string pat="%"+search+"%";sqlite3_bind_text(s,1,pat.c_str(),-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,pat.c_str(),-1,SQLITE_TRANSIENT);}std::string out="[";bool first=true;while(sqlite3_step(s)==SQLITE_ROW){if(!first)out+=",";first=false;out+="{\"id\":"+std::to_string(sqlite3_column_int(s,0))+",\"username\":"+js(col(s,1))+",\"email\":"+js(col(s,2))+",\"role\":"+js(col(s,3))+",\"created_at\":"+js(col(s,4))+",\"scan_count\":"+std::to_string(sqlite3_column_int(s,5))+"}";}sqlite3_finalize(s);return responseJson(200,out+"]");}
 if(r.method=="POST"&&p=="/api/admin/users"){auto e=needAdmin();if(!e.empty())return e;std::string username=trim(field(body,"username")),email=trim(field(body,"email")),password=field(body,"password"),role=field(body,"role")=="admin"?"admin":"user";if(username.empty()||password.empty())return error(400,"Username and password are required");sqlite3_stmt*s=nullptr;sqlite3_prepare_v2(db,"SELECT id FROM users WHERE username=?",-1,&s,nullptr);sqlite3_bind_text(s,1,username.c_str(),-1,SQLITE_TRANSIENT);bool ex=sqlite3_step(s)==SQLITE_ROW;sqlite3_finalize(s);if(ex)return error(409,"Username is already taken");auto h=hashPassword(password);sqlite3_int64 id=0;if(h.empty()||run("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",{username,email,h,role},&id)<0)return error(500,"Failed to create user");return responseJson(201,"{\"message\":"+js("User created successfully with role "+role)+",\"user\":{\"id\":"+std::to_string(id)+",\"username\":"+js(username)+",\"email\":"+js(email)+",\"role\":"+js(role)+"}}") ;}
 if(r.method=="PATCH"&&p.rfind("/api/admin/users/",0)==0&&p.find("/role")!=std::string::npos){auto e=needAdmin();if(!e.empty())return e;auto start=std::string("/api/admin/users/").size();int id=std::atoi(p.substr(start,p.find("/role")-start).c_str());std::string role=field(body,"role");if(role!="user"&&role!="admin")return error(400,"Role must be either \"user\" or \"admin\"");if(id==u.id&&role!="admin")return error(400,"Security policy: You cannot demote your own active administrator account");int n=run("UPDATE users SET role=? WHERE id=?",{role,std::to_string(id)});return n?responseJson(200,"{\"message\":"+js("User role updated to "+role+" successfully")+"}"):error(404,"User not found");}
 if(r.method=="DELETE"&&p.rfind("/api/admin/users/",0)==0){auto e=needAdmin();if(!e.empty())return e;int id=std::atoi(p.substr(std::string("/api/admin/users/").size()).c_str());if(id<=0)return error(400,"Invalid user ID");if(id==u.id)return error(400,"Security policy: You cannot delete your own active administrator account");run("DELETE FROM scans WHERE user_id=?",{std::to_string(id)});int n=run("DELETE FROM users WHERE id=?",{std::to_string(id)});return n?responseJson(200,"{\"message\":\"User account and associated records deleted successfully\"}"):error(404,"User not found");}
 if(r.method=="GET"&&p=="/api/admin/scans"){auto e=needAdmin();if(!e.empty())return e;std::string filter=query(r.path,"filter"),sql="SELECT s.id,u.username,s.url,s.is_phishing,s.security_score,s.result,s.timestamp FROM scans s JOIN users u ON s.user_id=u.id";if(filter=="phishing")sql+=" WHERE s.is_phishing=1";else if(filter=="safe")sql+=" WHERE s.is_phishing=0";sql+=" ORDER BY s.timestamp DESC LIMIT 50";sqlite3_stmt*s=nullptr;sqlite3_prepare_v2(db,sql.c_str(),-1,&s,nullptr);std::string out="[";bool f=true;while(sqlite3_step(s)==SQLITE_ROW){if(!f)out+=",";f=false;out+="{\"id\":"+std::to_string(sqlite3_column_int(s,0))+",\"username\":"+js(col(s,1))+",\"url\":"+js(col(s,2))+",\"isPhishing\":"+(sqlite3_column_int(s,3)?"true":"false")+",\"securityScore\":"+std::to_string(sqlite3_column_int(s,4))+",\"reasons\":"+reasons(col(s,5))+",\"timestamp\":"+js(col(s,6))+"}";}sqlite3_finalize(s);return responseJson(200,out+"]");}
 if(r.method=="GET"&&p=="/api/oop-info")return responseJson(200,"{\"message\":\"PRiVY C++ OOP architecture\",\"classes\":[\"User\",\"Admin\",\"ScanResult\",\"URLAnalyzer\",\"PhishingDetector\"]}");
 if(p.rfind("/api/",0)==0)return error(404,"API route not found: "+r.method+" "+r.path);
 if(r.method=="GET"){std::string file=p=="/"?"index.html":p=="/login"?"login.html":p=="/signup"?"signup.html":p=="/dashboard"?"dashboard.html":p=="/admin"?"admin.html":p.substr(p.find_last_of('/')==std::string::npos?0:p.find_last_of('/')+1);if(file.find("..")!=std::string::npos)return error(404,"Not found");std::string fpath=publicDir+"/"+file;std::ifstream in(fpath,std::ios::binary);if(in){std::ostringstream contents;contents<<in.rdbuf();std::string ct="text/plain; charset=utf-8";if(endsWith(file,".html"))ct="text/html; charset=utf-8";else if(endsWith(file,".css"))ct="text/css; charset=utf-8";else if(endsWith(file,".js"))ct="application/javascript; charset=utf-8";else if(endsWith(file,".svg"))ct="image/svg+xml";else if(endsWith(file,".png"))ct="image/png";else if(endsWith(file,".jpg")||endsWith(file,".jpeg"))ct="image/jpeg";return responseJson(200,contents.str(),ct);}}
 return error(404,"Not found");
}
} // namespace

int main(int argc,char**argv){
    int port=3000;
    if(argc>1) port=std::atoi(argv[1]);
    if(argc>2) dbPath=argv[2];
    if(const char*v=std::getenv("JWT_SECRET")) jwtSecret=v;
    if(const char*v=std::getenv("ADMIN_REGISTRATION_KEY")) adminKey=v;
    if(const char*v=std::getenv("DEFAULT_ADMIN_PASSWORD")) adminPassword=v;
    if(const char*v=std::getenv("PRIVY_PUBLIC_DIR")) publicDir=v;

#ifdef _WIN32
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2),&wsaData)!=0){std::cerr<<"WSAStartup failed\n";return 1;}
#endif

    if(sqlite3_open(dbPath.c_str(),&db)!=SQLITE_OK){std::cerr<<"Could not open SQLite database: "<<dbPath<<"\n";return 1;}
    initDb();

#ifdef _WIN32
    SOCKET server=(SOCKET)socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(server==INVALID_SOCKET){std::cerr<<"Socket creation failed\n";WSACleanup();return 1;}
    int opt=1;
    setsockopt(server,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt,sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_port=htons((u_short)port);
    if(bind(server,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR||listen(server,32)==SOCKET_ERROR){std::cerr<<"Could not bind port "<<port<<"\n";closesocket(server);WSACleanup();return 1;}
    std::cout<<"PRiVY C++ backend serving at http://localhost:"<<port<<std::endl;
    std::cout<<"Press Ctrl+C to stop."<<std::endl;
    while(true){
        SOCKET client=accept(server,nullptr,nullptr);
        if(client==INVALID_SOCKET) continue;
        std::string raw;
        char buf[4096];
        size_t len=0;
        bool hd=false;
        size_t headerEnd=std::string::npos;
        while(raw.size()<2*1024*1024){
            int n=recv(client,buf,sizeof(buf),0);
            if(n<=0) break;
            raw.append(buf,(size_t)n);
            headerEnd=raw.find("\r\n\r\n");
            if(headerEnd!=std::string::npos&&!hd){hd=true;auto pos=raw.find("Content-Length:");if(pos!=std::string::npos){pos+=15;while(pos<raw.size()&&std::isspace((unsigned char)raw[pos]))pos++;len=(size_t)std::strtoul(raw.c_str()+pos,nullptr,10);}}
            if(hd&&raw.size()>=headerEnd+4+len) break;
        }
        Request r;
        auto a=raw.find(' '),b=raw.find(' ',a==std::string::npos?a:a+1);
        r.method=a==std::string::npos?"":raw.substr(0,a);
        r.path=b==std::string::npos?"/":raw.substr(a+1,b-a-1);
        auto hEnd=raw.find("\r\n\r\n");
        if(hEnd!=std::string::npos){std::string headers=raw.substr(0,hEnd);auto auth=headers.find("Authorization:");if(auth!=std::string::npos){auth+=14;while(auth<headers.size()&&std::isspace((unsigned char)headers[auth]))auth++;auto e=headers.find("\r\n",auth);r.auth=headers.substr(auth,e==std::string::npos?e:e-auth);}r.body=raw.substr(hEnd+4,len);}
        sendAll((int)client,handle(r));
        closesocket(client);
    }
    closesocket(server);
    WSACleanup();
#else
    int server=socket(AF_INET,SOCK_STREAM,0);
    if(server<0){std::cerr<<"Socket creation failed\n";return 1;}
    int opt=1;
    setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    addr.sin_port=htons(port);
    if(bind(server,(sockaddr*)&addr,sizeof(addr))<0||listen(server,32)<0){std::cerr<<"Could not bind port "<<port<<"\n";return 1;}
    std::cout<<"PRiVY C++ backend serving at http://localhost:"<<port<<"\n";
    while(true){int client=accept(server,nullptr,nullptr);if(client<0)continue;std::string raw;char buf[4096];size_t len=0;bool hd=false;size_t headerEnd=std::string::npos;while(raw.size()<2*1024*1024){ssize_t n=recv(client,buf,sizeof(buf),0);if(n<=0)break;raw.append(buf,(size_t)n);headerEnd=raw.find("\r\n\r\n");if(headerEnd!=std::string::npos&&!hd){hd=true;auto pos=raw.find("Content-Length:");if(pos!=std::string::npos){pos+=15;while(pos<raw.size()&&std::isspace((unsigned char)raw[pos]))pos++;len=(size_t)std::strtoul(raw.c_str()+pos,nullptr,10);}}if(hd&&raw.size()>=headerEnd+4+len)break;}Request r;auto a=raw.find(' '),b=raw.find(' ',a==std::string::npos?a:a+1);r.method=a==std::string::npos?"":raw.substr(0,a);r.path=b==std::string::npos?"/":raw.substr(a+1,b-a-1);auto hEnd=raw.find("\r\n\r\n");if(hEnd!=std::string::npos){std::string headers=raw.substr(0,hEnd);auto auth=headers.find("Authorization:");if(auth!=std::string::npos){auth+=14;while(auth<headers.size()&&std::isspace((unsigned char)headers[auth]))auth++;auto e=headers.find("\r\n",auth);r.auth=headers.substr(auth,e==std::string::npos?e:e-auth);}r.body=raw.substr(hEnd+4,len);}sendAll(client,handle(r));close(client);}
    close(server);
#endif
    sqlite3_close(db);
    return 0;
}
