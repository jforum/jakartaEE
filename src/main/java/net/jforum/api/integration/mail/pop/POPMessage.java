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
 * Created on 21/08/2006 22:14:04
 * The JForum Project
 * http://www.jforum.net
 */
package net.jforum.api.integration.mail.pop;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.mail.Header;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.safety.Safelist;

import net.jforum.exceptions.MailException;
import net.jforum.util.preferences.ConfigKeys;
import net.jforum.util.preferences.SystemGlobals;

/**
 * Represents a pop message. 
 * @author Rafael Steil
 * @author Ulf Dittmer (attachment support)
 */
public class POPMessage
{
	private static final Logger LOGGER = Logger.getLogger(POPMessage.class);

	private static final String IN_REPLY_TO = "In-Reply-To";
	private static final String REFERENCES = "References";

	// Some mailers (like Yahoo) have a strange way of encoding the file name, using Base64 or URL-encoding
	// =?UTF-8?b?TGFuZGhhdXMgSGltbWVscGZvcnQucGRm?=
	// =?UTF-8?b?c2h1dHRlcnN0b2NrLmpwZw==?=
	// =?UTF-8?Q?upload=5Fwith=5Fumla?= =?UTF-8?Q?uts=5Fa=CC=88o=CC=88u=CC=88=C3=9Fe=CC=81.jpg?=
	// group(1) is the encoding, group(2) is the actual text, there can be multiple parts for long filenames
	private static final Pattern filenamePat = Pattern.compile("=\\?([^\\?]*)\\?.\\?([^\\?]*)\\?=");

	private String subject = "";
	private Object message;
	private transient String messageContents = "";
	private String sender;
	private String replyTo;
	private String references;
	private String inReplyTo;
	private String contentType;
	private transient String listEmail;
	private Date sendDate;
	private Map<String, String> headers;
	private int msgNumber;
	private ArrayList<POPAttachment> attachments;

	/**
	 * Creates a new instance based on a {@link Message}
	 * @param message the message to convert from.
	 */
	public POPMessage(final Message message)
	{
		this.extract(message);
	}

	/**
	 * Given a {@link Message}, converts it to our internal format
	 * @param message the message to convert
	 */
	private void extract(final Message message)
	{
		try {
			this.subject = message.getSubject();

			this.message = message.getContent();
			this.contentType = message.getContentType();
			this.sender = ((InternetAddress)message.getFrom()[0]).getAddress();
			this.listEmail = ((InternetAddress)message.getAllRecipients()[0]).getAddress();
			this.sendDate = message.getSentDate();
			this.msgNumber = message.getMessageNumber();

			if (message.getReplyTo().length > 0) {
				this.replyTo = ((InternetAddress)message.getReplyTo()[0]).getAddress();
			}
			else {
				this.replyTo = this.sender;
			}

			this.headers = new ConcurrentHashMap<>();

			for (final Enumeration<?> enumeration = message.getAllHeaders(); enumeration.hasMoreElements(); ) {
				final Header header = (Header)enumeration.nextElement();
				this.headers.put(header.getName(), header.getValue());
			}

			if (this.headers.containsKey(IN_REPLY_TO)) {
				this.inReplyTo = this.headers.get(IN_REPLY_TO);
			}

			if (this.headers.containsKey(REFERENCES)) {
				this.references = this.headers.get(REFERENCES);
			}

			// no longer used: doesn't handle attachments
			//this.extractMessageContents(message);

			this.attachments = new ArrayList<>();
			this.processParts(message.getContent());
		}
		catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
	}
/*
	private void extractMessageContents(final Message message) throws MessagingException
	{
		Part messagePart = message;

		if (this.message instanceof Multipart) {
			messagePart = ((Multipart)this.message).getBodyPart(0);
		}

		if (contentType.startsWith("text/html")
			|| contentType.startsWith("text/plain")
			|| contentType.startsWith("multipart")) {
			InputStream inputStream = null;
			BufferedReader reader = null;

			try {
				inputStream = messagePart.getInputStream();
				inputStream.reset();
				reader = new BufferedReader(
					new InputStreamReader(inputStream));

				final StringBuilder stringBuffer = new StringBuilder(512);
				int count = 0;
				final char[] chr = new char[2048];

				while ((count = reader.read(chr)) != -1) {
					stringBuffer.append(chr, 0, count);
				}

				this.messageContents = stringBuffer.toString();
			}
			catch (IOException e) {
				throw new MailException(e);
			}
			finally {
				if (reader != null) {
					try {
						reader.close();
					} catch (Exception e) {
						LOGGER.error(e.getMessage(), e);
					}
				}
				if (inputStream != null) {
					try {
						inputStream.close();
					} catch (Exception e) {
						LOGGER.error(e.getMessage(), e);
					}
				}
			}
		}
	}
*/
	private void processParts (Object content) throws Exception {
		if (content instanceof Multipart) {
			Multipart multi = ((Multipart)content);
			int parts = multi.getCount();
			for (int j=0; j<parts; j++) {
				MimeBodyPart part = (MimeBodyPart)multi.getBodyPart(j);
				if (part.getContent() instanceof Multipart) {
					// part-within-a-part, do some recursion...
					processParts(part.getContent());
				} else {
					String type = part.getContentType();
					//LOGGER.debug("type="+type);
					if (type.startsWith("text/plain") || type.startsWith("text/html")) {
						// fill in message body, if it doesn't exist yet
						if (StringUtils.isBlank(messageContents)) {
							Object partContent = part.getContent();
							if (partContent instanceof String) {
								this.messageContents = (String) partContent;
							} else if (partContent instanceof InputStream) {
								this.messageContents = new String(IOUtils.toByteArray((InputStream) partContent));
							}
							// remove HTML tags if necessary
							if (type.startsWith("text/html")) {
								Document.OutputSettings outputSettings = new Document.OutputSettings();
								outputSettings.prettyPrint(false);
								this.messageContents = Jsoup.clean(messageContents, "", Safelist.none(), outputSettings);
							}
						}
					} else {
						if (SystemGlobals.getBoolValue(ConfigKeys.MAIL_POP3_ATTACHMENTS)) {
							String fileName = part.getFileName();
							//LOGGER.debug("fileName="+fileName);
							Matcher matcher = filenamePat.matcher(fileName);
							String enc = null;
							try {
								StringBuilder sb = new StringBuilder(fileName.length()*2);
								while (matcher.find()) {
									enc = matcher.group(1);
									sb.append(matcher.group(2));
								}
								if (enc != null) {
									fileName = sb.toString();
									fileName = new String(Base64.getDecoder().decode(fileName), enc);
								}
							} catch (Exception ex) {
								try {
									String url = fileName.replaceAll("=", "%");
									fileName = URLDecoder.decode(url, StandardCharsets.UTF_8.name());
								} catch (Exception ex2) {
									//LOGGER.debug("nicht URL encoded: "+ex2.getMessage());
								}
							}
							POPAttachment attachment = new POPAttachment(fileName, type, IOUtils.toByteArray(part.getInputStream()));
							attachments.add(attachment);
							LOGGER.debug("reading "+attachment);
						}
					}
				}
			}
		}
	}

	public String getListEmail()
	{
		return this.listEmail;
	}

	/**
	 * @return the contentType
	 */
	public String getContentType()
	{
		return this.contentType;
	}

	/**
	 * @return the headers
	 */
	public Map<String, String> getHeaders()
	{
		return this.headers;
	}

	/**
	 * @return the attachments
	 */
	public ArrayList<POPAttachment> getAttachments()
	{
		return this.attachments;
	}

	/**
	 * @return the inReplyTo
	 */
	public String getInReplyTo()
	{
		return this.inReplyTo;
	}

	/**
	 * @return the message
	 */
	public String getMessage()
	{
		return this.messageContents;
	}

	/**
	 * @return the references
	 */
	public String getReferences()
	{
		return this.references;
	}

	/**
	 * @return the replyTo
	 */
	public String getReplyTo()
	{
		return this.replyTo;
	}

	/**
	 * @return the sendDate
	 */
	public Date getSendDate()
	{
		return this.sendDate;
	}

	/**
	 * @return the sender
	 */
	public String getSender()
	{
		return this.sender;
	}

	/**
	 * @return the subject
	 */
	public String getSubject()
	{
		return this.subject;
	}

	/**
	 * @param contentType the contentType to set
	 */
	public void setContentType(final String contentType)
	{
		this.contentType = contentType;
	}

	/**
	 * @param headers the headers to set
	 */
	public void setHeaders(final Map<String, String> headers)
	{
		this.headers = headers;
	}

	/**
	 * @param inReplyTo the inReplyTo to set
	 */
	public void setInReplyTo(final String inReplyTo)
	{
		this.inReplyTo = inReplyTo;
	}

	/**
	 * @param message the message to set
	 */
	public void setMessage(final Object message)
	{
		this.message = message;
	}

	/**
	 * @param references the references to set
	 */
	public void setReferences(final String references)
	{
		this.references = references;
	}

	/**
	 * @param replyTo the replyTo to set
	 */
	public void setReplyTo(final String replyTo)
	{
		this.replyTo = replyTo;
	}

	/**
	 * @param sendDate the sendDate to set
	 */
	public void setSendDate(final Date sendDate)
	{
		this.sendDate = sendDate;
	}

	/**
	 * @param sender the sender to set
	 */
	public void setSender(final String sender)
	{
		this.sender = sender;
	}

	/**
	 * @param subject the subject to set
	 */
	public void setSubject(final String subject)
	{
		this.subject = subject;
	}

	public int getMessageNumber()
	{
		return this.msgNumber;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override public String toString()
	{
		return new StringBuilder()
			.append('[')
			.append("subject=").append(this.subject)
			.append(", sender=").append(this.sender)
			.append(", replyTo=").append(this.replyTo)
			.append(", references=").append(this.references)
			.append(", inReplyTo=").append(this.inReplyTo)
			.append(", contentType=").append(this.contentType)
			.append(", date=").append(this.sendDate)
			.append(", content=").append(this.messageContents)
			.append(", headers=").append(this.headers)
			.append(']')
			.toString();
	}

	/**
	 * Class for encapsulating a mail attachment
	 */
	public class POPAttachment {
		private String fileName;
		private String mimeType;
		private byte[] data;

		public POPAttachment (String fileName, String mimeType, byte[] data) {
			this.fileName = fileName;
			this.mimeType = mimeType;
			this.data = data;
		}

		public String getFileName() { return this.fileName; }
		public String getMimeType() { return this.mimeType; }
		public byte[] getData() { return this.data; }

		@Override
		public String toString() {
			return this.fileName + ", " + this.mimeType + ", size " + this.data.length;
		}
	}
}
