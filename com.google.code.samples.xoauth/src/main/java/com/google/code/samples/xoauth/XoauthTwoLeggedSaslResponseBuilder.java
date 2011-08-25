/* Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.code.samples.xoauth;

import static net.oauth.OAuth.HMAC_SHA1;
import static net.oauth.OAuth.OAUTH_SIGNATURE_METHOD;

import net.oauth.ConsumerProperties;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;


/**
 * Builds the XOAUTH SASL client response. This class has no internal state.
 */
public class XoauthTwoLeggedSaslResponseBuilder {
  /**
   * Builds an XOAUTH SASL client response for two legged challenge.
   *
   * @param userEmail The email address of the user, for example
   *     "xoauth@gmail.com".
   * @param protocol The XoauthProtocol for which to generate an authentication
   *     string.
   * @param consumerKey The OAuth consumerKey
   * @param consumerSecret The OAuth consumerSecret
   * 
   * @return A byte array containing the auth string suitable for being returned
   * from {@code SaslClient.evaluateChallenge}. It needs to be base64-encoded
   * before actually being sent over the network.
   */
  public byte[] buildResponse(
		  String userEmail,
	      XoauthProtocol protocol,
          String consumerKey,
          String consumerSecret)
          throws IOException, OAuthException, URISyntaxException {

      OAuthConsumer consumer = new OAuthConsumer(null, consumerKey, consumerSecret, null);
      OAuthAccessor accessor = new OAuthAccessor(consumer);
      
      accessor.consumer.setProperty(OAUTH_SIGNATURE_METHOD, HMAC_SHA1);

      String url = String.format(
              "https://mail.google.com/mail/b/%s/%s/?xoauth_requestor_id=%s",
              userEmail,
              protocol.getName(),
              OAuth.percentEncode(userEmail));

      OAuthMessage message = new OAuthMessage(
              "GET",
              url,
              null);
      message.addRequiredParameters(accessor);

      StringBuilder authString = new StringBuilder();
      authString.append("GET ");
      authString.append(url);
      authString.append(" ");
      int i = 0;
      for (Map.Entry<String, String> entry : message.getParameters()) {
          if (i++ > 0) {
              authString.append(",");
          }
          authString.append(OAuth.percentEncode(entry.getKey()));
          authString.append("=\"");
          authString.append(OAuth.percentEncode(entry.getValue()));
          authString.append("\"");
      }
      return authString.toString().getBytes();
  }
}
