/*
 * Copyright (c) JForum Team
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * 1) Redistributions of source code must retain the above 
 * copyright notice, this list of conditions and the 
 * following disclaimer.
 * 2) Redistributions in binary form must reproduce the 
 * above copyright notice, this list of conditions and 
 * the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 * 3) Neither the name of "Rafael Steil" nor 
 * the names of its contributors may be used to endorse 
 * or promote products derived from this software without 
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT 
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
 * THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 * 
 * Created on 21/08/2006 21:08:19
 * The JForum Project
 * http://www.jforum.net
 */
package net.jforum.api.integration.mail.pop;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import jakarta.mail.Flags;
import jakarta.mail.Flags;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.internet.InternetAddress;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import net.jforum.dao.DataAccessDriver;
import net.jforum.dao.UserDAO;
import net.jforum.entities.MailIntegration;
import net.jforum.entities.User;
import net.jforum.exceptions.MailException;
import net.jforum.util.preferences.ConfigKeys;
import net.jforum.util.preferences.SystemGlobals;

/**
 * Handles the connection to the POP server.
 * 
 * @author Rafael Steil
 */
public class POPConnector
{
	private static final Logger LOGGER = Logger.getLogger(POPConnector.class);

	private transient Store store;
	private transient Folder folder;
	private transient MailIntegration mailIntegration;
	private transient Message[] messages;

	/**
	 * @param mailIntegration the {@link MailIntegration} instance with 
	 * all the information necessary to connect to the pop server
	 */
	public void setMailIntegration(final MailIntegration mailIntegration)
	{
		this.mailIntegration = mailIntegration;
	}

	/**
	 * Lists all available messages in the pop server
	 * @return Array of {@link Message}'s
	 */
	public Message[] listMessages()
	{
		try {
			this.messages = this.folder.getMessages();
			return Arrays.copyOf(this.messages, this.messages.length);
		}
		catch (Exception e) {
			throw new MailException(e);
		}
	}

	/**
	 * Opens a connection to the pop server. 
	 * The method will try to retrieve the <i>INBOX</i> folder in <i>READ_WRITE</i> mode
	 */
	public void openConnection()
	{
		try {
			final Properties props = new Properties();
			// fix DEBUG POP3: server doesn't support TOP, disabling it
			props.setProperty(ConfigKeys.MAIL_POP3_DISABLETOP, SystemGlobals.getValue(ConfigKeys.MAIL_POP3_DISABLETOP));
			final Session session = Session.getDefaultInstance(props);

			this.store = session.getStore(this.mailIntegration.isSsl() ? "pop3s" : "pop3");

			this.store.connect(this.mailIntegration.getPopHost(), 
					this.mailIntegration.getPopPort(), 
					this.mailIntegration.getPopUsername(),
					this.mailIntegration.getPopPassword());

			this.folder = this.store.getFolder("INBOX");

			if (folder == null) {
				throw new Exception("No Inbox");
			}
			/*
			Flags flags = folder.getPermanentFlags();
			LOGGER.debug("POP3 INBOX folder flags: system "+Arrays.toString(flags.getSystemFlags())+", user "+Arrays.toString(flags.getUserFlags()));
			*/

			this.folder.open(Folder.READ_WRITE);
		}
		catch (Exception e) {
			throw new MailException(e);
		}
	}

	/**
	 * Closes the connection to the pop server.
	 * Before finishing the communication channel, all messages that have been imported are flagged for deletion.
	 */
	public void closeConnection(Collection<Integer> imported)
	{
		final boolean deleteMessages = !SystemGlobals.getBoolValue(ConfigKeys.MAIL_POP3_DEBUG_KEEP_MESSAGES);
		this.closeConnection(deleteMessages, imported);
	}

	/**
	 * Closes the connection to the pop server.
	 * @param deleteAll If true, all messages are flagged for deletion
	 */
	public void closeConnection(final boolean deleteAll, final Collection<Integer> imported)
	{
		if (deleteAll) {
			this.markAllMessagesAsDeleted(imported);
		}

		if (this.folder != null) {
			try {
				this.folder.close(deleteAll);
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
			}
		}
		if (this.store != null) {
			try {
				this.store.close();
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
			}
		}
	}

	/**
	 * Flag all messages for deletion.
	 */
	private void markAllMessagesAsDeleted(final Collection<Integer> imported)
	{
		try {
			if (this.messages != null) {
				UserDAO userDao = DataAccessDriver.getInstance().newUserDAO();
				for (Message msg : messages) {
					// don't delete message if the user is unknown
					User user = userDao.findByEmail(((InternetAddress) msg.getFrom()[0]).getAddress());
					if (user != null && imported.contains(msg.getMessageNumber())) {
						msg.setFlag(Flags.Flag.DELETED, true);
						LOGGER.debug("deleting mail "+msg.getSubject());
					}
				}
			}
		} catch (Exception e) {
			throw new MailException(e);
		}
	}
}
