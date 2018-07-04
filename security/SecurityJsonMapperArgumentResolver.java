package com.tuniu.finance.xff.auth.security;

import com.tiefan.fbs.fsp.base.core.argument.JsonMapperArgumentResolver;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.ArrayList;
import java.util.List;


public class SecurityJsonMapperArgumentResolver extends JsonMapperArgumentResolver {
    private SimpleBeanSecurityHelper httpSecurityHelper;

    public SimpleBeanSecurityHelper getHttpSecurityHelper() {
        return httpSecurityHelper;
    }

    public void setHttpSecurityHelper(SimpleBeanSecurityHelper httpSecurityHelper) {
        this.httpSecurityHelper = httpSecurityHelper;
    }

    @SuppressWarnings("unchecked")
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
        Object value = super.resolveArgument(parameter, mavContainer, webRequest, binderFactory);
        Object decrypted = null;
        if (value instanceof List) {
            List<Object> decryptedList = new ArrayList<Object>();
            for (Object obj : (List<Object>) value) {
                decryptedList.add(httpSecurityHelper.decrypt(obj));
            }
            decrypted = decryptedList;
        } else {
            decrypted = httpSecurityHelper.decrypt(value);
        }
        return decrypted;
    }
}
