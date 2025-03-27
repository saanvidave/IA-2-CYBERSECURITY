pWS-SECURITY Fackage com.example.wssecurity;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SecureServiceClient {
    public static void main(String[] args) {
        String serviceURL = "http://localhost:8080/secureService";

        // Create client proxy
        JaxWsProxyFactoryBean factory = new JaxWsProxyFactoryBean();
        factory.setServiceClass(SecureService.class);
        factory.setAddress(serviceURL);

        SecureService client = (SecureService) factory.create();

        // Add WS-Security (Username Token)
        Client proxy = ClientProxy.getClient(client);
        Map<String, Object> outProps = new HashMap<>();
        outProps.put(ConfigurationConstants.ACTION, ConfigurationConstants.USERNAME_TOKEN);
        outProps.put(ConfigurationConstants.USER, "admin");
        outProps.put(ConfigurationConstants.PW_CALLBACK_CLASS, ClientPasswordCallback.class.getName());

        WSS4JOutInterceptor wssOut = new WSS4JOutInterceptor(outProps);
        proxy.getOutInterceptors().add(wssOut);

        // Call the service
        System.out.println(client.sayHello("Saanvi"));
    }

    public static class ClientPasswordCallback implements CallbackHandler {
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof WSPasswordCallback) {
                    WSPasswordCallback pc = (WSPasswordCallback) callback;
                    if ("admin".equals(pc.getIdentifier())) {
                        pc.setPassword("password123");
                    }
                }
            }
        }
    }
}
