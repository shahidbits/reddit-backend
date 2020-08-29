package com.example.reddit.config;

import org.slf4j.MDC;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

public class MdcInterceptor implements HandlerInterceptor {

    private static final String CORRELATION_ID_HEADER = "X-CORRELATION.ID";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        MDC.put("CorrelationId", getCorrelationId(request));
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        MDC.remove("CorrelationId");
    }

    private String getCorrelationId(HttpServletRequest request) {
        String currentCorrId = request.getHeader(CORRELATION_ID_HEADER);
        if (StringUtils.isEmpty(currentCorrId)) {
            return UUID.randomUUID().toString();
        }
        return currentCorrId;
    }
}