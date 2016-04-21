package me.lcw.dtls;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutionException;

import org.threadly.concurrent.PriorityScheduler;
import org.threadly.litesockets.Client;
import org.threadly.litesockets.Server.ClientAcceptor;
import org.threadly.litesockets.ThreadedSocketExecuter;
import org.threadly.litesockets.UDPClient;
import org.threadly.litesockets.UDPServer;
import org.threadly.litesockets.utils.MergedByteBuffers;
import org.threadly.litesockets.utils.PortUtils;

import me.lcw.dtls.DTLSWrapper.BufferReader;

public class MainTest {
  
  public static void main(String[] args) throws IOException, InterruptedException, ExecutionException {
    PriorityScheduler PS = new PriorityScheduler(10);
    ThreadedSocketExecuter TSE = new ThreadedSocketExecuter(PS); 
    TSE.start();
    int port = PortUtils.findUDPPort();

    UDPServer s1 = TSE.createUDPServer("localhost", port);
    s1.start();
    
    s1.setClientAcceptor(new ClientAcceptor() {
      @Override
      public void accept(Client client) {
        final DTLSWrapper tmp = new DTLSWrapper((UDPClient)client, "/tmp/cert.pem", "/tmp/nopwkey.pem");
        tmp.setClientMode(false);
        tmp.startEncryption();
        tmp.setBufferReader(new BufferReader() {
          @Override
          public void onData(ByteBuffer bb) {
            MergedByteBuffers mbb = new MergedByteBuffers();
            mbb.add(bb);
            try {
              tmp.write(bb.duplicate());
            } catch (IOException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            }
            System.out.println("Server:::::"+mbb.getAsString(mbb.remaining()));
          }});
      }});

    
    int port2 = PortUtils.findUDPPort();
    UDPServer s2 = TSE.createUDPServer("localhost", port2);
    s2.start();
    
    UDPClient udpc1 = s2.createUDPClient("localhost", port);
    
    final DTLSWrapper dtls1 = new DTLSWrapper(udpc1, "/tmp/cert.pem", "/tmp/nopwkey.pem");
    
    dtls1.setBufferReader(new BufferReader() {
      @Override
      public void onData(ByteBuffer bb) {
        MergedByteBuffers mbb = new MergedByteBuffers();
        mbb.add(bb);
        System.out.println("CLIENT:::::"+mbb.getAsString(mbb.remaining()));

      }});
    
    dtls1.setClientMode(true);
    
    dtls1.startEncryption().get();


    
    dtls1.write(ByteBuffer.wrap("TEST".getBytes()));
    
    Thread.sleep(20000);
  }

}
