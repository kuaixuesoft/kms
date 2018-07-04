package com.tuniu.finance.xff.auth.security;

import com.sun.xml.xsom.impl.scd.Iterators.Map;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.executor.keygen.NoKeyGenerator;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.springframework.util.Assert;

import java.beans.PropertyDescriptor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

@Intercepts({@Signature(type= Executor.class,method = "update",args = {MappedStatement.class,Object.class}),
					@Signature(type= Executor.class,method = "query",
					args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class})})
public class SecurityPlugin implements Interceptor {
	private AbstractBeanSecurityHelper dbSecurityHelper;

	protected boolean filterByParameter(Object parameter){
        return !(parameter instanceof Map
                || parameter instanceof Collection
                || parameter instanceof Number
                || parameter instanceof String);
	}
	
	protected Object interceptUpdate(Invocation invocation) throws Throwable{
		final MappedStatement mappedStatement = (MappedStatement)invocation.getArgs()[0];
		Object parameter = invocation.getArgs()[1];
		
        Object encrypted = dbSecurityHelper.encrypt(parameter);
        invocation.getArgs()[1] = encrypted;
        Object ret = invocation.proceed();
        Object decrypted = dbSecurityHelper.decrypt(parameter);
        invocation.getArgs()[1] = decrypted;
		/*更新自增长键值*/
		if((mappedStatement.getKeyGenerator() instanceof NoKeyGenerator)==false){
			String keyProperty = mappedStatement.getKeyProperties()[0];
			PropertyDescriptor pd = new PropertyDescriptor(keyProperty, parameter.getClass());
			Object val = pd.getReadMethod().invoke(encrypted);
			pd.getWriteMethod().invoke(parameter, val);
		}
		
		return ret;
	}
	
	@SuppressWarnings("rawtypes")
	protected Object interceptQuery(Invocation invocation) throws Throwable{
		Object result = invocation.proceed();
		Assert.notNull(result);
/*		if(result instanceof Number){
			return result;
		}*/
		List<Object> decryptedList = new ArrayList<Object>();
		for(Object obj: (List)result){
			decryptedList.add(dbSecurityHelper.decrypt(obj));
		}
		return decryptedList;
	}
	
	@Override
	public Object intercept(Invocation invocation) throws Throwable {
		if(invocation.getMethod().getName().equals("update")){
			if(filterByParameter(invocation.getArgs()[1])){
				return interceptUpdate(invocation);
			}
			else{
				return invocation.proceed();
			}
		}
		else if(invocation.getMethod().getName().equals("query")){
			return interceptQuery(invocation);
		}
		else{
			throw new RuntimeException("not supported invocation: "+invocation.getMethod().toString());
		}
	}

	@Override
	public Object plugin(Object target) {
		 return Plugin.wrap(target, this);
	}

	@Override
	public void setProperties(Properties properties) {
	}

	
	public AbstractBeanSecurityHelper getDbSecurityHelper() {
		return dbSecurityHelper;
	}

	public void setDbSecurityHelper(AbstractBeanSecurityHelper dbSecurityHelper) {
		this.dbSecurityHelper = dbSecurityHelper;
	}
}
