    LOG("~TlsAgent()");
    if (adapter_) {
      Poller::Instance()->Cancel(READABLE_EVENT, adapter_);
    }

    if (pr_fd_) {
      PR_Close(pr_fd_);
    }

    if (ssl_fd_) {
      PR_Close(ssl_fd_);
    }

    if (timer_)
      timer_->Cancel();
  }

  bool Init() {
    pr_fd_ = DummyPrSocket::CreateFD(name_, mode_);
    if (!pr_fd_) return false;

    adapter_ = DummyPrSocket::GetAdapter(pr_fd_);
    if (!adapter_) return false;

    return true;
  }

  void SetPeer(TlsAgent* peer) { adapter_->SetPeer(peer->adapter_); }

  void SetInspector(Inspector* inspector) { adapter_->SetInspector(inspector); }

  void StartConnect() {
    ASSERT_TRUE(EnsureTlsSetup());

    SECStatus rv;
    rv = SSL_ResetHandshake(ssl_fd_, role_ == SERVER ? PR_TRUE : PR_FALSE);
    ASSERT_EQ(SECSuccess, rv);
    SetState(CONNECTING);
  }

  void EnableSomeECDHECiphers() {
    ASSERT_TRUE(EnsureTlsSetup());

    const uint32_t EnabledCiphers[] = {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA};

    for (size_t i = 0; i < PR_ARRAY_SIZE(EnabledCiphers); ++i) {
      SECStatus rv = SSL_CipherPrefSet(ssl_fd_, EnabledCiphers[i], PR_TRUE);
      ASSERT_EQ(SECSuccess, rv);
    }
  }

  void EnableCompression() {
    SECStatus rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_DEFLATE, PR_TRUE);
    ASSERT_EQ(SECSuccess, rv);
  }

  bool EnsureTlsSetup() {
    // Don't set up twice
    if (ssl_fd_) return true;

    if (adapter_->mode() == STREAM) {
      ssl_fd_ = SSL_ImportFD(nullptr, pr_fd_);
    } else {
      ssl_fd_ = DTLS_ImportFD(nullptr, pr_fd_);
    }

    EXPECT_NE(nullptr, ssl_fd_);
    if (!ssl_fd_) return false;
    pr_fd_ = nullptr;

    if (role_ == SERVER) {
      CERTCertificate* cert = PK11_FindCertFromNickname(name_.c_str(), nullptr);
      EXPECT_NE(nullptr, cert);
      if (!cert) return false;

      SECKEYPrivateKey* priv = PK11_FindKeyByAnyCert(cert, nullptr);
      EXPECT_NE(nullptr, priv);
      if (!priv) return false;  // Leak cert.

      SECStatus rv = SSL_ConfigSecureServer(ssl_fd_, cert, priv, kt_rsa);
      EXPECT_EQ(SECSuccess, rv);
      if (rv != SECSuccess) return false;  // Leak cert and key.

      SECKEY_DestroyPrivateKey(priv);
      CERT_DestroyCertificate(cert);
    } else {
      SECStatus rv = SSL_SetURL(ssl_fd_, "server");
      EXPECT_EQ(SECSuccess, rv);
      if (rv != SECSuccess) return false;
    }

    SECStatus rv = SSL_AuthCertificateHook(ssl_fd_, AuthCertificateHook,
                                           reinterpret_cast<void*>(this));
    EXPECT_EQ(SECSuccess, rv);
    if (rv != SECSuccess) return false;

    return true;
  }

  void SetVersionRange(uint16_t minver, uint16_t maxver) {
    ASSERT_TRUE(EnsureTlsSetup());

    SSLVersionRange range = {minver, maxver};
    ASSERT_EQ(SECSuccess, SSL_VersionRangeSet(ssl_fd_, &range));
  }

  State state() const { return state_; }
  int32_t err_code() const { return err_code_; }

  const char* state_str() const { return state_str(state()); }

  const char* state_str(State state) const { return states[state]; }

  PRFileDesc* ssl_fd() { return ssl_fd_; }

  bool version(uint16_t* version) const {
    if (state_ != CONNECTED) return false;

    *version = info_.protocolVersion;

    return true;
  }

  bool cipher_suite(int16_t* cipher_suite) const {
    if (state_ != CONNECTED) return false;

    *cipher_suite = info_.cipherSuite;
    return true;
  }

  std::string cipher_suite_name() const {
    if (state_ != CONNECTED) return "UNKNOWN";

    return csinfo_.cipherSuiteName;
  }

  bool is_compressed() const {
    return info_.compressionMethod != ssl_compression_null;
  }

  void CheckKEAType(SSLKEAType type) const {
    ASSERT_EQ(CONNECTED, state_);
    ASSERT_EQ(type, csinfo_.keaType);
  }

  void CheckVersion(uint16_t version) const {
    ASSERT_EQ(CONNECTED, state_);
    ASSERT_EQ(version, info_.protocolVersion);
  }


  void Handshake() {
    SECStatus rv = SSL_ForceHandshake(ssl_fd_);
    if (rv == SECSuccess) {
      LOG("Handshake success");
      SECStatus rv = SSL_GetChannelInfo(ssl_fd_, &info_, sizeof(info_));
      ASSERT_EQ(SECSuccess, rv);

      rv = SSL_GetCipherSuiteInfo(info_.cipherSuite, &csinfo_, sizeof(csinfo_));
      ASSERT_EQ(SECSuccess, rv);

      SetState(CONNECTED);

      if (mode_ == STREAM) {
          Poller::Instance()->Wait(READABLE_EVENT, adapter_, this,
                                   &TlsAgent::ReadableCallback);
      }
      return;
    }

    int32_t err = PR_GetError();
    switch (err) {
      case PR_WOULD_BLOCK_ERROR:
        LOG("Would have blocked");
        // TODO(ekr@rtfm.com): set DTLS timeouts
        Poller::Instance()->Wait(READABLE_EVENT, adapter_, this,
                                 &TlsAgent::ReadableCallback);
        return;
        break;

      // TODO(ekr@rtfm.com): needs special case for DTLS
      case SSL_ERROR_RX_MALFORMED_HANDSHAKE:
      default:
        LOG("Handshake failed with error " << err);
        SetState(ERROR);
        err_code_ = err;
        return;
    }
  }

  std::vector<uint8_t> GetSessionId() {
    return std::vector<uint8_t>(info_.sessionID,
                                info_.sessionID + info_.sessionIDLength);
  }

  void ConfigureSessionCache(SessionResumptionMode mode) {
    ASSERT_TRUE(EnsureTlsSetup());

    SECStatus rv = SSL_OptionSet(ssl_fd_,
                                 SSL_NO_CACHE,
                                 mode & RESUME_SESSIONID ?
                                 PR_FALSE : PR_TRUE);
    ASSERT_EQ(SECSuccess, rv);

    rv = SSL_OptionSet(ssl_fd_,
                       SSL_ENABLE_SESSION_TICKETS,
                       mode & RESUME_TICKET ?
                       PR_TRUE : PR_FALSE);
    ASSERT_EQ(SECSuccess, rv);
  }

  void EnableExtendedMasterSecret() {
    ASSERT_TRUE(EnsureTlsSetup());

    // TODO(ekr@rtfm.com): Temporary. Remove when we have session hash for
    // other versions.
    SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                    SSL_LIBRARY_VERSION_TLS_1_2);

    SECStatus rv = SSL_OptionSet(ssl_fd_,
                                 SSL_ENABLE_EXTENDED_MASTER_SECRET,
                                 PR_TRUE);

    ASSERT_EQ(SECSuccess, rv);
  }

  void CheckExtendedMasterSecret(bool expected) {
    std::cerr << "Checking extended master secret for " << name_ << " expected=" << expected << std::endl;
    ASSERT_EQ(expected, info_.extendedMasterSecretUsed)
        << "unexpected extended master secret state for " << name_;
  }

  void SendData(size_t bytes) {
    uint8_t block[1024];

    while(bytes) {
      size_t tosend = std::min(sizeof(block), bytes);

      for(size_t i=0; i<tosend; ++i) {
        block[i] = 0xff & send_ctr_;
        ++send_ctr_;
      }

      LOG("Writing " << tosend << " bytes");
      int32_t rv = PR_Write(ssl_fd_, block, tosend);
      ASSERT_EQ(tosend, rv);

      bytes -= tosend;
    }
  }

  size_t received_bytes() const { return recv_ctr_; }

 private:
  const static char* states[];

  void SetState(State state) {
    if (state_ == state) return;

    LOG("Changing state from " << state_str(state_) << " to "
                               << state_str(state));
    state_ = state;
  }

  // Dummy auth certificate hook.
  static SECStatus AuthCertificateHook(void* arg, PRFileDesc* fd,
                                       PRBool checksig, PRBool isServer) {
    return SECSuccess;
  }

  static void ReadableCallback(PollTarget* self, Event event) {
    TlsAgent* agent = static_cast<TlsAgent*>(self);
    agent->ReadableCallback_int(event);
  }

  void ReadableCallback_int(Event event) {
    LOG("Readable");
    switch (state_) {
      case CONNECTING:
        Handshake();
        break;
      case CONNECTED:
        if (mode_ == STREAM) {
          ReadBytes();
        }
        break;
      default:
        break;
    }
  }

  void ReadBytes() {
    uint8_t block[1024];

    LOG("Reading application data from socket");

    int32_t rv = PR_Read(ssl_fd_, block, sizeof(block));
    ASSERT_LE(0, rv);

    LOG("Read " << rv << " bytes");
    for (size_t i=0; i<rv; ++i) {
      ASSERT_EQ((recv_ctr_ & 0xff), block[i]);
      recv_ctr_++;
    }

    Poller::Instance()->Wait(READABLE_EVENT, adapter_, this,
                             &TlsAgent::ReadableCallback);
  }

  const std::string name_;
  Mode mode_;
  PRFileDesc* pr_fd_;
  DummyPrSocket* adapter_;
  PRFileDesc* ssl_fd_;
  Role role_;
  State state_;
  int32_t err_code_;
  SSLChannelInfo info_;
  SSLCipherSuiteInfo csinfo_;
  size_t send_ctr_;
  size_t recv_ctr_;
};

const char* TlsAgent::states[] = {"INIT", "CONNECTING", "CONNECTED", "ERROR"};

class TlsConnectTestBase : public ::testing::Test {
 public:
  TlsConnectTestBase(Mode mode)
      : mode_(mode),
        client_(new TlsAgent("client", TlsAgent::CLIENT, mode_)),
        server_(new TlsAgent("server", TlsAgent::SERVER, mode_)),
        session_ids_(),
        expect_extended_master_secret_(false) {}

  ~TlsConnectTestBase() {
    delete client_;
    delete server_;
  }

  void SetUp() {
    // Configure a fresh session cache.
    SSL_ConfigServerSessionIDCache(1024, 0, 0, g_working_dir_path.c_str());

    // Clear statistics.
    SSL3Statistics* stats = SSL_GetStatistics();
    memset(stats, 0, sizeof(*stats));

    Init();
  }

  void TearDown() {

    client_ = nullptr;
    server_ = nullptr;

    SSL_ClearSessionCache();
    SSL_ShutdownServerSessionIDCache();
  }

  void Init() {
    ASSERT_TRUE(client_->Init());
    ASSERT_TRUE(server_->Init());

    client_->SetPeer(server_);
    server_->SetPeer(client_);
  }

  void Reset() {
    delete client_;
    delete server_;

    client_ = new TlsAgent("client", TlsAgent::CLIENT, mode_);
    server_ = new TlsAgent("server", TlsAgent::SERVER, mode_);

    Init();
  }

  void EnsureTlsSetup() {
    ASSERT_TRUE(client_->EnsureTlsSetup());
    ASSERT_TRUE(server_->EnsureTlsSetup());
  }

  void ConnectInt() {
    server_->StartConnect();  // Server
    client_->StartConnect();  // Client
    client_->Handshake();
    server_->Handshake();

    ASSERT_TRUE_WAIT((client_->state() != TlsAgent::CONNECTING) &&
                     (server_->state() != TlsAgent::CONNECTING),
                     5000);
  }

  void Connect() {
    ConnectInt();
    ASSERT_EQ(TlsAgent::CONNECTED, client_->state());
    ASSERT_EQ(TlsAgent::CONNECTED, server_->state());

    int16_t cipher_suite1, cipher_suite2;
    bool ret = client_->cipher_suite(&cipher_suite1);
    ASSERT_TRUE(ret);
    ret = server_->cipher_suite(&cipher_suite2);
    ASSERT_TRUE(ret);
    ASSERT_EQ(cipher_suite1, cipher_suite2);

    std::cerr << "Connected with cipher suite " << client_->cipher_suite_name()
              << std::endl;

    // Check and store session ids.
    std::vector<uint8_t> sid_c1 = client_->GetSessionId();
    ASSERT_EQ(32, sid_c1.size());
    std::vector<uint8_t> sid_s1 = server_->GetSessionId();
    ASSERT_EQ(32, sid_s1.size());
    ASSERT_EQ(sid_c1, sid_s1);
    session_ids_.push_back(sid_c1);

    // Check whether the extended master secret extension was negotiated.
    CheckExtendedMasterSecret();
  }

  void ConnectExpectFail(int32_t client_status=0, int32_t server_status=0) {
    server_->StartConnect(); // Server
    client_->StartConnect(); // Client
    client_->Handshake();
    server_->Handshake();

    ASSERT_TRUE_WAIT(client_->state() != TlsAgent::CONNECTING &&
                     server_->state() != TlsAgent::CONNECTING, 5000);
    ASSERT_EQ(TlsAgent::ERROR, server_->state());
    if (client_status) {
      ASSERT_EQ(client_status, client_->err_code());
    }
    if (server_status) {
      ASSERT_EQ(server_status, server_->err_code());
    }
  }

  void EnableSomeECDHECiphers() {
    client_->EnableSomeECDHECiphers();
    server_->EnableSomeECDHECiphers();
  }

  void ConfigureSessionCache(SessionResumptionMode client,
                             SessionResumptionMode server) {
    client_->ConfigureSessionCache(client);
    server_->ConfigureSessionCache(server);
  }

  void CheckResumption(SessionResumptionMode expected) {
    ASSERT_NE(RESUME_BOTH, expected);

    int resume_ct = expected != 0;
    int stateless_ct = (expected & RESUME_TICKET) ? 1 : 0;

    SSL3Statistics* stats = SSL_GetStatistics();
    ASSERT_EQ(resume_ct, stats->hch_sid_cache_hits);
    ASSERT_EQ(resume_ct, stats->hsh_sid_cache_hits);

    ASSERT_EQ(stateless_ct, stats->hch_sid_stateless_resumes);
    ASSERT_EQ(stateless_ct, stats->hsh_sid_stateless_resumes);

    if (resume_ct) {
      // Check that the last two session ids match.
      ASSERT_GE(2, session_ids_.size());
      ASSERT_EQ(session_ids_[session_ids_.size()-1],
                session_ids_[session_ids_.size()-2]);
    }
  }

  void ExpectExtendedMasterSecret(bool expected) {
    expect_extended_master_secret_ = expected;
  }

 protected:
  void CheckExtendedMasterSecret() {
    client_->CheckExtendedMasterSecret(expect_extended_master_secret_);
    server_->CheckExtendedMasterSecret(expect_extended_master_secret_);
  }


  Mode mode_;
  TlsAgent* client_;
  TlsAgent* server_;
  std::vector<std::vector<uint8_t>> session_ids_;
  bool expect_extended_master_secret_;
};

class TlsConnectTest : public TlsConnectTestBase {
 public:
  TlsConnectTest() : TlsConnectTestBase(STREAM) {}

  void SendReceive() {
    client_->SendData(50);
    server_->SendData(50);
    WAIT_(
        client_->received_bytes() == 50 &&
        server_->received_bytes() == 50, 2000);
    ASSERT_EQ(50, client_->received_bytes());
    ASSERT_EQ(50, server_->received_bytes());
  }
};

class DtlsConnectTest : public TlsConnectTestBase {
 public:
  DtlsConnectTest() : TlsConnectTestBase(DGRAM) {}
};

class TlsConnectGeneric : public TlsConnectTestBase,
                          public ::testing::WithParamInterface<std::string> {
 public:
  TlsConnectGeneric()
      : TlsConnectTestBase((GetParam() == "TLS") ? STREAM : DGRAM) {
    std::cerr << "Variant: " << GetParam() << std::endl;
  }
};

TEST_P(TlsConnectGeneric, SetupOnly) {}

TEST_P(TlsConnectGeneric, Connect) {
  Connect();

  // Check that we negotiated the expected version.
  if (mode_ == STREAM) {
    client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_0);
  } else {
    client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_1);
  }
}

TEST_P(TlsConnectGeneric, ConnectResumed) {
  ConfigureSessionCache(RESUME_SESSIONID, RESUME_SESSIONID);
  Connect();

  Reset();
  Connect();
  CheckResumption(RESUME_SESSIONID);
}

TEST_P(TlsConnectGeneric, ConnectClientCacheDisabled) {
  ConfigureSessionCache(RESUME_NONE, RESUME_SESSIONID);
  Connect();
  Reset();
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectServerCacheDisabled) {
  ConfigureSessionCache(RESUME_SESSIONID, RESUME_NONE);
  Connect();
  Reset();
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectSessionCacheDisabled) {
  ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
  Connect();
  Reset();
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectResumeSupportBoth) {
  // This prefers tickets.
  ConfigureSessionCache(RESUME_BOTH, RESUME_BOTH);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_BOTH, RESUME_BOTH);
  Connect();
  CheckResumption(RESUME_TICKET);
}

TEST_P(TlsConnectGeneric, ConnectResumeClientTicketServerBoth) {
  // This causes no resumption because the client needs the
  // session cache to resume even with tickets.
  ConfigureSessionCache(RESUME_TICKET, RESUME_BOTH);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_TICKET, RESUME_BOTH);
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectResumeClientBothTicketServerTicket) {
  // This causes a ticket resumption.
  ConfigureSessionCache(RESUME_BOTH, RESUME_TICKET);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_BOTH, RESUME_TICKET);
  Connect();
  CheckResumption(RESUME_TICKET);
}

TEST_P(TlsConnectGeneric, ConnectClientServerTicketOnly) {
  // This causes no resumption because the client needs the
  // session cache to resume even with tickets.
  ConfigureSessionCache(RESUME_TICKET, RESUME_TICKET);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_TICKET, RESUME_TICKET);
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectClientBothServerNone) {
  ConfigureSessionCache(RESUME_BOTH, RESUME_NONE);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_BOTH, RESUME_NONE);
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectClientNoneServerBoth) {
  ConfigureSessionCache(RESUME_NONE, RESUME_BOTH);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_NONE, RESUME_BOTH);
  Connect();
  CheckResumption(RESUME_NONE);
}

TEST_P(TlsConnectGeneric, ConnectExtendedMasterSecret) {
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  Connect();

  Reset();
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  Connect();
  CheckResumption(RESUME_SESSIONID);
}

TEST_P(TlsConnectGeneric, ConnectExtendedMasterSecretECDHE) {
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  EnableSomeECDHECiphers();
  Connect();

  Reset();
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  EnableSomeECDHECiphers();
  Connect();
  CheckResumption(RESUME_SESSIONID);
}

TEST_P(TlsConnectGeneric, ConnectExtendedMasterSecretTicket) {
  ConfigureSessionCache(RESUME_BOTH, RESUME_TICKET);
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  Connect();

  Reset();
  ConfigureSessionCache(RESUME_BOTH, RESUME_TICKET);
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  Connect();
  CheckResumption(RESUME_TICKET);
}

TEST_P(TlsConnectGeneric, ConnectExtendedMasterSecretClientOnly) {
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                    SSL_LIBRARY_VERSION_TLS_1_2);
  server_->EnableSomeECDHECiphers();

  client_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(false);
  Connect();
}

TEST_P(TlsConnectGeneric, ConnectExtendedMasterSecretServerOnly) {
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                    SSL_LIBRARY_VERSION_TLS_1_2);
  client_->EnableSomeECDHECiphers();

  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(false);
  Connect();
}

TEST_P(TlsConnectGeneric, ConnectExtendedMasterSecretResumeWithout) {
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  Connect();

  Reset();
  server_->EnableExtendedMasterSecret();
  ConnectExpectFail();
}

TEST_P(TlsConnectGeneric, ConnectNormalResumeWithExtendedMasterSecret) {
  ExpectExtendedMasterSecret(false);
  Connect();

  Reset();
  client_->EnableExtendedMasterSecret();
  server_->EnableExtendedMasterSecret();
  ExpectExtendedMasterSecret(true);
  Connect();
  CheckResumption(RESUME_NONE);
}


TEST_P(TlsConnectGeneric, ConnectTLS_1_1_Only) {
  EnsureTlsSetup();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_1);

  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_1);

  Connect();

  client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_1);
}

TEST_P(TlsConnectGeneric, ConnectTLS_1_2_Only) {
  EnsureTlsSetup();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                           SSL_LIBRARY_VERSION_TLS_1_2);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_2,
                           SSL_LIBRARY_VERSION_TLS_1_2);
  Connect();
  client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_2);
}


<<<<<<< HEAD
// This succeeds even with TLS 1.3 enabled because we
// don't default to having TLS 1.3 on.
TEST_P(TlsConnectGeneric, ConnectWithCompression)
{
  EnsureTlsSetup();
  client_->EnableCompression();
  server_->EnableCompression();
  Connect();
  ASSERT_TRUE(client_->is_compressed());
}

#define SKIP_DTLS() if (mode_ != STREAM) return

#ifdef NSS_ENABLE_TLS_1_3
TEST_P(TlsConnectGeneric, ConnectTLS_1_3_Only)
{
  SKIP_DTLS();
  EnsureTlsSetup();
  EnableSomeECDHECiphers();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_3);
}

TEST_P(TlsConnectGeneric, ConnectTLS_1_3_ServerOnly)
{
  SKIP_DTLS();
  EnsureTlsSetup();
  EnableSomeECDHECiphers();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_3);
}

TEST_P(TlsConnectGeneric, ConnectTLS_1_3_ServerOnlyMismatch)
{
  SKIP_DTLS();
  EnsureTlsSetup();
  // Only enable ECDHE on server.
  server_->EnableSomeECDHECiphers();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  ConnectExpectFail(SSL_ERROR_NO_CYPHER_OVERLAP,
                    SSL_ERROR_NO_CYPHER_OVERLAP);
}


TEST_P(TlsConnectGeneric, ConnectTLS_1_3_WithCompressionOn)
{
  SKIP_DTLS();
  EnsureTlsSetup();
  EnableSomeECDHECiphers();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_1,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);

  client_->EnableCompression();
  server_->EnableCompression();
  Connect();
  ASSERT_FALSE(client_->is_compressed());
}
#endif

=======
>>>>>>> 8005466... Fix crasher and DTLS record detection
TEST_F(TlsConnectTest, ConnectECDHE) {
  EnableSomeECDHECiphers();
  Connect();
  client_->CheckKEAType(ssl_kea_ecdh);
}

TEST_F(TlsConnectTest, ConnectECDHETwiceReuseKey) {
  EnableSomeECDHECiphers();
  TlsInspectorRecordHandshakeMessage* i1 =
      new TlsInspectorRecordHandshakeMessage(kTlsHandshakeServerKeyExchange);
  server_->SetInspector(i1);
  Connect();
  client_->CheckKEAType(ssl_kea_ecdh);
  TlsServerKeyExchangeECDHE dhe1;
  ASSERT_TRUE(dhe1.Parse(i1->buffer().data(), i1->buffer().len()));

  // Restart
  Reset();
  TlsInspectorRecordHandshakeMessage* i2 =
      new TlsInspectorRecordHandshakeMessage(kTlsHandshakeServerKeyExchange);
  server_->SetInspector(i2);
  EnableSomeECDHECiphers();
  ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
  Connect();
  client_->CheckKEAType(ssl_kea_ecdh);

  TlsServerKeyExchangeECDHE dhe2;
  ASSERT_TRUE(dhe2.Parse(i2->buffer().data(), i2->buffer().len()));

  // Make sure they are the same.
  ASSERT_EQ(dhe1.public_key_.len(), dhe2.public_key_.len());
  ASSERT_TRUE(!memcmp(dhe1.public_key_.data(), dhe2.public_key_.data(),
                      dhe1.public_key_.len()));
}

TEST_F(TlsConnectTest, ConnectECDHETwiceNewKey) {
  EnableSomeECDHECiphers();
  SECStatus rv =
      SSL_OptionSet(server_->ssl_fd(), SSL_REUSE_SERVER_ECDHE_KEY, PR_FALSE);
  ASSERT_EQ(SECSuccess, rv);
  TlsInspectorRecordHandshakeMessage* i1 =
      new TlsInspectorRecordHandshakeMessage(kTlsHandshakeServerKeyExchange);
  server_->SetInspector(i1);
  Connect();
  client_->CheckKEAType(ssl_kea_ecdh);
  TlsServerKeyExchangeECDHE dhe1;
  ASSERT_TRUE(dhe1.Parse(i1->buffer().data(), i1->buffer().len()));

  // Restart
  Reset();
  EnableSomeECDHECiphers();
  rv = SSL_OptionSet(server_->ssl_fd(), SSL_REUSE_SERVER_ECDHE_KEY, PR_FALSE);
  ASSERT_EQ(SECSuccess, rv);
  TlsInspectorRecordHandshakeMessage* i2 =
      new TlsInspectorRecordHandshakeMessage(kTlsHandshakeServerKeyExchange);
  server_->SetInspector(i2);
  ConfigureSessionCache(RESUME_NONE, RESUME_NONE);
  Connect();
  client_->CheckKEAType(ssl_kea_ecdh);

  TlsServerKeyExchangeECDHE dhe2;
  ASSERT_TRUE(dhe2.Parse(i2->buffer().data(), i2->buffer().len()));

  // Make sure they are different.
  ASSERT_FALSE((dhe1.public_key_.len() == dhe2.public_key_.len()) &&
               (!memcmp(dhe1.public_key_.data(), dhe2.public_key_.data(),
                        dhe1.public_key_.len())));
}

TEST_F(TlsConnectTest, ConnectSendReceive) {
  Connect();
  SendReceive();
}

#ifdef NSS_ENABLE_TLS_1_3
TEST_F(TlsConnectTest, ConnectSendReceiveTLS_1_3)
{
  SKIP_DTLS();
  EnsureTlsSetup();
  EnableSomeECDHECiphers();
  client_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  server_->SetVersionRange(SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3);
  Connect();
  SendReceive();
  client_->CheckVersion(SSL_LIBRARY_VERSION_TLS_1_3);
}
#endif

INSTANTIATE_TEST_CASE_P(Variants, TlsConnectGeneric,
                        ::testing::Values("TLS", "DTLS"));

}  // namespace nspr_test
