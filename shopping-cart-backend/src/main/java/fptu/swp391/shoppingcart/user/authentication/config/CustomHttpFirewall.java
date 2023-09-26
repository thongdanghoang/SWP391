package fptu.swp391.shoppingcart.user.authentication.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.stereotype.Component;

@Component
public class CustomHttpFirewall implements HttpFirewall {
    @Override
    public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
        return new RequestWrapper(request);
    }

    @Override
    public HttpServletResponse getFirewalledResponse(HttpServletResponse response) {
        return new ResponseWrapper(response);
    }
}
