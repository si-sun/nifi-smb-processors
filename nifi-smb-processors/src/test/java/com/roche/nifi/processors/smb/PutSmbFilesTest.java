/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.roche.nifi.processors.smb;

import com.hierynomus.smbj.share.File;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.isNotNull;
import static org.mockito.Mockito.any;
import org.mockito.ArgumentCaptor;

import org.apache.nifi.processor.ProcessContext;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Set;


public class PutSmbFilesTest {

    private TestRunner testRunner;
    private static final Logger logger = LoggerFactory.getLogger(PutSmbFilesTest.class);

    private ProcessContext processContext;
    private SMBClient smbClient;
    private Connection connection;
    private Session session;
    private DiskShare diskShare;
    private File smbfile;
    private ByteArrayOutputStream baOutputStream;

    private final static String HOSTNAME = "smbhostname";
    private final static String SHARE = "smbshare";
    private final static String DIRECTORY = "smbdirectory\\subdir";
    private final static String DOMAIN = "mydomain";
    private final static String USERNAME = "myusername";
    private final static String PASSWORD = "mypassword";


    private void setupSmbProcessor() throws IOException {
        processContext = mock(ProcessContext.class);
        smbClient = mock(SMBClient.class);
        connection = mock(Connection.class);
        session = mock(Session.class);
        diskShare = mock(DiskShare.class);
        smbfile = mock(File.class);
        baOutputStream = new ByteArrayOutputStream();

        when(smbClient.connect(any(String.class))).thenReturn(connection);
        when(connection.authenticate(any(AuthenticationContext.class))).thenReturn(session);
        when(session.connectShare(SHARE)).thenReturn(diskShare);
        when(diskShare.openFile(
                any(String.class)
                ,anySet()
                ,anySet()
                ,anySet()
                ,any(SMB2CreateDisposition.class)
                ,anySet()
        )).thenReturn(smbfile);
        when(smbfile.getOutputStream()).thenReturn(baOutputStream);

        testRunner.setProperty(PutSmbFiles.HOSTNAME, HOSTNAME);
        testRunner.setProperty(PutSmbFiles.SHARE, SHARE);
        testRunner.setProperty(PutSmbFiles.DIRECTORY, DIRECTORY);
        testRunner.setProperty(PutSmbFiles.DOMAIN, DOMAIN);
        testRunner.setProperty(PutSmbFiles.USERNAME, USERNAME);
        testRunner.setProperty(PutSmbFiles.PASSWORD, PASSWORD);
        

        PutSmbFiles putSmbFiles = (PutSmbFiles) testRunner.getProcessor();
        putSmbFiles.initSmbClient(smbClient);
    }

    private void testDirectoryCreation(String dirFlag, int times) throws IOException {
        when(diskShare.folderExists(DIRECTORY)).thenReturn(false);

        testRunner.setProperty(PutSmbFiles.CREATE_DIRS, dirFlag);
        testRunner.enqueue("data");
        testRunner.run();

        verify(diskShare, times(times)).mkdir(DIRECTORY);
    }

    private Set<SMB2ShareAccess> testOpenFileShareAccess() throws IOException {
        ArgumentCaptor<Set<SMB2ShareAccess>> shareAccessSet = ArgumentCaptor.forClass(Set.class);

        testRunner.enqueue("data");
        testRunner.run();

        verify(diskShare, times(1)).openFile(
            any(String.class)
            ,anySet()
            ,anySet()
            ,shareAccessSet.capture()
            ,any(SMB2CreateDisposition.class)
            ,anySet()
        );
        return shareAccessSet.getValue();
    }

    @Before
    public void init() throws IOException {
        testRunner = TestRunners.newTestRunner(PutSmbFiles.class);
        setupSmbProcessor();
    }

    @Test
    public void testNormalAuth() throws IOException {
        ArgumentCaptor<AuthenticationContext> ac = ArgumentCaptor.forClass(AuthenticationContext.class);

        testRunner.enqueue("data");
        testRunner.run();
        
        verify(connection).authenticate(ac.capture());
        AuthenticationContext acObj = ac.getValue();
        assertEquals(acObj.getUsername(), USERNAME);
        assertEquals(acObj.	getDomain(), DOMAIN);
        assertArrayEquals(acObj.getPassword(), PASSWORD.toCharArray());
    }

    @Test
    public void testAnonymousAuth() throws IOException {
        ArgumentCaptor<AuthenticationContext> ac = ArgumentCaptor.forClass(AuthenticationContext.class);

        testRunner.removeProperty(PutSmbFiles.USERNAME);
        testRunner.enqueue("data");
        testRunner.run();
        
        verify(connection).authenticate(ac.capture());
        AuthenticationContext acObj = ac.getValue();
        AuthenticationContext compAc = AuthenticationContext.anonymous();
        assertEquals(acObj.getUsername(), compAc.getUsername());
        assertEquals(acObj.getDomain(), compAc.getDomain());
        assertArrayEquals(acObj.getPassword(), compAc.getPassword());
    }

    @Test
    public void testDirExistsWithoutCreate() throws IOException {
        testDirectoryCreation("false", 0);
    }

    @Test
    public void testDirExistsWithCreate() throws IOException {
        testDirectoryCreation("true", 1);
    }

    @Test
    public void testFileShareNone() throws IOException {
        testRunner.setProperty(PutSmbFiles.SHARE_ACCESS, PutSmbFiles.SHARE_ACCESS_NONE);
        Set<SMB2ShareAccess> shareAccessSet = testOpenFileShareAccess();
        assertTrue(shareAccessSet.isEmpty());
    }

    @Test
    public void testFileShareRead() throws IOException {
        testRunner.setProperty(PutSmbFiles.SHARE_ACCESS, PutSmbFiles.SHARE_ACCESS_READ);
        Set<SMB2ShareAccess> shareAccessSet = testOpenFileShareAccess();
        assertTrue(shareAccessSet.contains(SMB2ShareAccess.FILE_SHARE_READ));
    }

    @Test
    public void testFileShareReadWriteDelete() throws IOException {
        testRunner.setProperty(PutSmbFiles.SHARE_ACCESS, PutSmbFiles.SHARE_ACCESS_READWRITEDELETE);
        Set<SMB2ShareAccess> shareAccessSet = testOpenFileShareAccess();
        assertTrue(shareAccessSet.contains(SMB2ShareAccess.FILE_SHARE_READ));
        assertTrue(shareAccessSet.contains(SMB2ShareAccess.FILE_SHARE_WRITE));
        assertTrue(shareAccessSet.contains(SMB2ShareAccess.FILE_SHARE_DELETE));
    }

    @Test
    public void testFileExistsFail() throws IOException {
        testRunner.setProperty(PutSmbFiles.CONFLICT_RESOLUTION, PutSmbFiles.FAIL_RESOLUTION);
        when(diskShare.fileExists(any(String.class))).thenReturn(true);
        testRunner.assertAllFlowFilesTransferred(PutSmbFiles.REL_FAILURE);
    }

    @Test
    public void testFileExistsIgnore() throws IOException {
        testRunner.setProperty(PutSmbFiles.CONFLICT_RESOLUTION, PutSmbFiles.IGNORE_RESOLUTION);
        when(diskShare.fileExists(any(String.class))).thenReturn(true);
        testRunner.assertAllFlowFilesTransferred(PutSmbFiles.REL_SUCCESS);
    }

    @Test
    public void testConnectionError() throws IOException {
        String emsg = "mock connection exception";
        when(smbClient.connect(any(String.class))).thenThrow(new IOException(emsg));
        
        testRunner.enqueue("1");
        testRunner.enqueue("2");
        testRunner.enqueue("3");
        testRunner.run();

        testRunner.assertAllFlowFilesTransferred(PutSmbFiles.REL_FAILURE, 3);
    }
}
