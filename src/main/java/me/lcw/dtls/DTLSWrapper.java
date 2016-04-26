package me.lcw.dtls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.crypto.tls.DTLSClientProtocol;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.threadly.concurrent.SubmitterScheduler;
import org.threadly.concurrent.future.ListenableFuture;
import org.threadly.concurrent.future.SettableListenableFuture;
import org.threadly.litesockets.Client;
import org.threadly.litesockets.Client.CloseListener;
import org.threadly.litesockets.Client.Reader;
import org.threadly.litesockets.UDPClient;
import org.threadly.litesockets.utils.MergedByteBuffers;

public class DTLSWrapper {
  private static final BufferFilter DEFAULT_BUFFER_FILTER = new LocalBufferFilter();
  private final AtomicBoolean encryptionStarted = new AtomicBoolean(false);
  private final SecureRandom secureRandom = new SecureRandom();
  private final LocalDatagramTransport  ldt = new LocalDatagramTransport();
  private final SettableListenableFuture<Boolean> handShakeFuture = new SettableListenableFuture<Boolean>();
  
  private final UDPClient client;
  private final String certFile;
  private final String keyFile;
  
  private volatile BufferFilter bufferFilter = DEFAULT_BUFFER_FILTER; 
  private volatile BufferReader bufferReader;
  private volatile boolean serverMode = false;
  private volatile DTLSTransport dtlsTransport;

  public DTLSWrapper(UDPClient client) {
    this(client, null, null);
  }
  
  public DTLSWrapper(UDPClient client, String certFile, String keyFile) {
    this.client = client;
    this.client.addCloseListener(new LocalCloseListener());
    this.client.setReader(new LocalReader());
    this.certFile = certFile;
    this.keyFile = keyFile;
  }

  public ListenableFuture<Boolean> startEncryption() {
    if(encryptionStarted.compareAndSet(false, true)) {
      final SubmitterScheduler SS = client.getClientsSocketExecuter().getThreadScheduler();
      if(serverMode) {
        final DTLSServerWrapper ms = new DTLSServerWrapper(keyFile, certFile);
        final DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);
        //final LoggingDatagramTransport transport = new LoggingDatagramTransport(ldt, new Object(), "server", System.err);
        SS.execute(new Runnable() {
          @Override
          public void run() {
            try {
              dtlsTransport = serverProtocol.accept(ms, ldt);
              handShakeFuture.setResult(true);
            } catch (IOException e) {
              handShakeFuture.setFailure(e);
            }
          }});
        

      } else {
        final DTLSClientWrapper mc = new DTLSClientWrapper(keyFile, certFile);
        final DTLSClientProtocol protocol = new DTLSClientProtocol(secureRandom);
        //final LoggingDatagramTransport transport = new LoggingDatagramTransport(ldt, new Object(), "client", System.err);
        SS.execute(new Runnable() {

          @Override
          public void run() {
            try {
              dtlsTransport = protocol.connect(mc, ldt);   
              handShakeFuture.setResult(true);
            } catch (IOException e) {
              handShakeFuture.setFailure(e);
            }
          }});

      }
    }
    return handShakeFuture;
  }

  public void setClientMode(boolean clientMode) {
    if(!this.encryptionStarted.get()) {
      if(!clientMode && (keyFile == null || certFile == null)) {
        throw new IllegalStateException("Key File and CertFile must be set to enter Server mode!");
      }
      serverMode = !clientMode;
    }
  }

  public void setBufferReader(BufferReader br) {
    this.bufferReader = br;
  }
  
  public void setBufferFilter(BufferFilter bf) {
    if(bf == null) {
      this.bufferFilter = DEFAULT_BUFFER_FILTER;
    } else {
      this.bufferFilter = bf;
    }
  }
  
  public void write(ByteBuffer bb) throws IOException {
    if(handShakeFuture.isDone() && dtlsTransport != null && bb.hasRemaining()) {
      byte[] ba = new byte[bb.remaining()];
      bb.get(ba);
      dtlsTransport.send(ba, 0, ba.length);
    } else {
      if(this.encryptionStarted.get()) {
        throw new IllegalStateException("Handshake must complete first!");
      } else {
        client.write(bb);
      }
    }
  }

  public class LocalDatagramTransport implements DatagramTransport {

    private final ArrayDeque<ByteBuffer> queue = new ArrayDeque<ByteBuffer>();

    @Override
    public int getReceiveLimit() throws IOException {
      return client.clientOptions().getUdpFrameSize();
    }

    @Override
    public int getSendLimit() throws IOException {
      return client.clientOptions().getUdpFrameSize();
    }

    protected void addData(ByteBuffer bb) {
      synchronized(queue) {
        queue.add(bb);
        queue.notifyAll();
      }
    }

    @Override
    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
      synchronized(queue) {
        if(queue.size() == 0 && waitMillis > 0) {
          try {
            queue.wait(waitMillis);
          } catch (InterruptedException e) {
            throw new IOException(e);
          }
        }
        if(queue.size() > 0) {
          ByteBuffer bb = queue.pop();
          int size = Math.min(len, bb.remaining());
          bb.get(buf, off, size);
          return size;
        }
      }
      if(client.isClosed()) {
        return -1;
      } else {
        return 0;
      }
    }

    @Override
    public void send(byte[] buf, int off, int len) throws IOException {
      ByteBuffer bb = ByteBuffer.allocate(len);
      bb.put(buf, off, len);
      bb.flip();
      client.write(bb);
    }

    @Override
    public void close() throws IOException {
      client.close();
    }

  }

  public class LocalReader implements Reader {
    @Override
    public void onRead(Client client) {
      MergedByteBuffers mbb = client.getRead();
      if(!encryptionStarted.get()) {
        bufferFilter.filterBuffer(mbb.pull(mbb.remaining()));
      } else {
        if(!handShakeFuture.isDone()) {
          ldt.addData(bufferFilter.filterBuffer(mbb.pull(mbb.remaining())));
        } else {
          final ByteBuffer ogbb = DEFAULT_BUFFER_FILTER.filterBuffer(bufferFilter.filterBuffer(mbb.pull(mbb.remaining())));
          if(ogbb != null && ogbb.hasRemaining()) {
            ldt.addData(ogbb);
            try {
              final int frameSize = client.clientOptions().getUdpFrameSize();
              
              byte[] ba = new byte[frameSize];
              int size = dtlsTransport.receive(ba, 0, frameSize, 0);
              ByteBuffer bb = ByteBuffer.wrap(ba);
              bb.limit(size);
              if( bufferReader != null) {
                bufferReader.onData(bb);
              }
            } catch (IOException e) {
              e.printStackTrace();
            }
          }
        } 
      }
    }
  }

  public class LocalCloseListener implements CloseListener {
    @Override
    public void onClose(Client client) {
    }
  }

  private static class LocalBufferFilter implements BufferFilter {
    ByteBuffer bbz = ByteBuffer.allocate(0);
    @Override
    public ByteBuffer filterBuffer(ByteBuffer bb) {
      byte b = bb.get(0);
      if(b > 19 && b < 64) {
        return bb;
      } else {
        return bbz;
      }
    }

  }

  public static interface BufferFilter {
    public ByteBuffer filterBuffer(ByteBuffer bb);
  }

  public static interface BufferReader {
    public void onData(ByteBuffer bb);
  }

}
