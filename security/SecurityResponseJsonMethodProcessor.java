package com.tuniu.finance.xff.auth.security;

import com.tiefan.fbs.fsp.base.core.method.ResponseJsonMethodProcessor;
import com.tiefan.fbs.fsp.base.core.utils.Response;
import org.springframework.core.MethodParameter;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.ArrayList;
import java.util.List;


public class SecurityResponseJsonMethodProcessor extends ResponseJsonMethodProcessor {
    private SimpleBeanSecurityHelper httpSecurityHelper;

    public SimpleBeanSecurityHelper getHttpSecurityHelper() {
        return httpSecurityHelper;
    }

    public void setHttpSecurityHelper(SimpleBeanSecurityHelper httpSecurityHelper) {
        this.httpSecurityHelper = httpSecurityHelper;
    }

    @SuppressWarnings("unchecked")
    public void handleReturnValue(Object returnValue, MethodParameter returnType, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest) throws Exception {
        if (returnValue != null && returnValue instanceof Response) {
            Response vo = (Response) returnValue;
            Object data = vo.getData();
            if (data != null) {
                if (data instanceof List) {
                    List<Object> encryptedList = new ArrayList<Object>();
                    for (Object obj : (List<Object>) data) {
                        encryptedList.add(httpSecurityHelper.encrypt(obj));
                    }
                    vo.setData(encryptedList);
                } else {
                    Object encrypted = httpSecurityHelper.encrypt(data);
                    vo.setData(encrypted);
                }
            }

            super.handleReturnValue(vo, returnType, mavContainer, webRequest);
        } else {
            super.handleReturnValue(returnValue, returnType, mavContainer, webRequest);
        }
    }
}
