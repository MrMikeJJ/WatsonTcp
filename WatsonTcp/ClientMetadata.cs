namespace WatsonTcp
{
    using System;
    using System.IO;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using WatsonTcp.Message;

    internal class ClientMetadata : IDisposable
    {
        #region Private-Fields

        private bool _Disposed = false;

        private readonly TcpClient _TcpClient;
        private readonly NetworkStream _NetworkStream;
        private readonly SslStream _SslStream;
        private readonly Stream _TrafficStream;

        private readonly string _IpPort;

        private readonly SemaphoreSlim _ReadLock = new SemaphoreSlim(1);
        private readonly SemaphoreSlim _WriteLock = new SemaphoreSlim(1);

        #endregion

        #region Constructors

        internal ClientMetadata(TcpClient tcp, Mode mode, bool acceptInvalidCertificates)
        {
            _TcpClient = tcp ?? throw new ArgumentNullException(nameof(tcp));
            _NetworkStream = tcp.GetStream();
            _IpPort = tcp.Client.RemoteEndPoint.ToString();

            if (mode == Mode.Tcp)
            {
                _TrafficStream = _NetworkStream;
            }
            else
            {
                if (acceptInvalidCertificates)
                {
                    _SslStream = new SslStream(_NetworkStream, false, new RemoteCertificateValidationCallback(AcceptCertificate));
                }
                else
                {
                    _SslStream = new SslStream(_NetworkStream, false);
                }

                _TrafficStream = _SslStream;
            }
        }

        #endregion

        #region Internal-Properties

        internal TcpClient TcpClient => _TcpClient;

        internal SslStream SslStream => _SslStream;

        internal Stream TrafficStream => _TrafficStream;

        internal string IpPort => _IpPort;

        internal SemaphoreSlim ReadLock => _ReadLock;

        internal SemaphoreSlim WriteLock => _WriteLock;

        #endregion

        #region Public-Methods

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region Protected-Methods

        protected virtual void Dispose(bool disposing)
        {
            if (_Disposed)
            {
                return;
            }

            if (disposing)
            {
                if (_SslStream != null)
                {
                    _SslStream.Close();
                }

                if (_NetworkStream != null)
                {
                    _NetworkStream.Close();
                }

                if (_TcpClient != null)
                {
                    _TcpClient.Close();
                }
            }

            ReadLock.Dispose();
            WriteLock.Dispose();

            _Disposed = true;
        }

        #endregion

        #region Internal-Methods

        internal async Task<WatsonMessage> MessageReadAsync(bool readDataStream)
        {
            WatsonMessage msg = new WatsonMessage(TrafficStream);
            await msg.Build(readDataStream);
            return msg;
        }

        internal bool MessageWrite(byte[] data, int readStreamBufferSize)
        {
            int dataLen = 0;
            using (MemoryStream ms = new MemoryStream())
            {
                if (data != null && data.Length > 0)
                {
                    dataLen = data.Length;
                    ms.Write(data, 0, data.Length);
                    ms.Seek(0, SeekOrigin.Begin);
                }

                WatsonMessage msg = new WatsonMessage(dataLen, ms);
                return MessageWrite(msg, readStreamBufferSize);
            }
        }

        internal bool MessageWrite(WatsonMessage msg, int readStreamBufferSize)
        {
            if (msg == null)
            {
                throw new ArgumentNullException(nameof(msg));
            }

            if (msg.ContentLength > 0)
            {
                if (msg.DataStream == null || !msg.DataStream.CanRead)
                {
                    throw new ArgumentException("Cannot read from supplied stream.");
                }
            }

            byte[] headerBytes = msg.ToHeaderBytes(msg.ContentLength);

            int bytesRead = 0;
            long bytesRemaining = msg.ContentLength;
            byte[] buffer = new byte[readStreamBufferSize];

            _WriteLock.Wait(1);

            try
            {
                _TrafficStream.Write(headerBytes, 0, headerBytes.Length);

                if (msg.ContentLength > 0)
                {
                    while (bytesRemaining > 0)
                    {
                        bytesRead = msg.DataStream.Read(buffer, 0, buffer.Length);
                        if (bytesRead > 0)
                        {
                            _TrafficStream.Write(buffer, 0, bytesRead);
                            bytesRemaining -= bytesRead;
                        }
                    }
                }

                _TrafficStream.Flush();

                return true;
            }
            catch (Exception e)
            {
                Common.Log($"*** MessageWrite {_IpPort} disconnected due to exception: {e.Message}");
                return false;
            }
            finally
            {
                _WriteLock.Release();
            }
        }

        internal async Task<bool> MessageWriteAsync(byte[] data, int readStreamBufferSize)
        {
            int dataLen = 0;
            using (MemoryStream ms = new MemoryStream())
            {
                if (data != null && data.Length > 0)
                {
                    dataLen = data.Length;
                    ms.Write(data, 0, data.Length);
                    ms.Seek(0, SeekOrigin.Begin);
                }

                WatsonMessage msg = new WatsonMessage(dataLen, ms);
                return await MessageWriteAsync(msg, readStreamBufferSize);
            }
        }

        internal async Task<bool> MessageWriteAsync(WatsonMessage msg, int readStreamBufferSize)
        {
            if (msg == null)
            {
                throw new ArgumentNullException(nameof(msg));
            }

            if (msg.ContentLength > 0)
            {
                if (msg.DataStream == null || !msg.DataStream.CanRead)
                {
                    throw new ArgumentException("Cannot read from supplied stream.");
                }
            }

            byte[] headerBytes = msg.ToHeaderBytes(msg.ContentLength);

            int bytesRead = 0;
            long bytesRemaining = msg.ContentLength;
            byte[] buffer = new byte[readStreamBufferSize];

            try
            {
                await _WriteLock.WaitAsync();
                await _TrafficStream.WriteAsync(headerBytes, 0, headerBytes.Length);

                if (msg.ContentLength > 0)
                {
                    while (bytesRemaining > 0)
                    {
                        bytesRead = await msg.DataStream.ReadAsync(buffer, 0, buffer.Length);
                        if (bytesRead > 0)
                        {
                            await _TrafficStream.WriteAsync(buffer, 0, bytesRead);
                            bytesRemaining -= bytesRead;
                        }
                    }
                }

                await _TrafficStream.FlushAsync();

                Common.Log($"MessageWriteAsync sent {Encoding.UTF8.GetString(headerBytes)}");
                return true;
            }
            catch (Exception e)
            {
                Common.Log($"*** MessageWriteAsync {_IpPort} disconnected due to exception: {e.Message}");
                return false;
            }
            finally
            {
                _WriteLock.Release();
            }
        }

        #endregion

        #region Private-Methods

        private bool AcceptCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Allow untrusted certificates.
            return true;
        }

        #endregion
    }
}
