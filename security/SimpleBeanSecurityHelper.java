package com.tuniu.finance.xff.auth.security;

import java.lang.reflect.Field;
import java.util.List;

import org.springframework.util.Assert;

public class SimpleBeanSecurityHelper extends AbstractBeanSecurityHelper{
	
	@Override
	protected void encryptSingle(Object obj) throws EncryptException {
		Assert.notNull(obj);
		Class<?> clazz = obj.getClass();

		List<Field> securityFields = processSecurityAnnotation(clazz);
		for(Field field: securityFields){
			ISecurityStrategy strategy = fieldSecurityStrategyMap.get(field);				
			Object value = getFieldValue(obj, field);
			Object encryptedValue = null;
			if(value!=null){
				encryptedValue = strategy.encrypt((String)value);
			}
			setFieldValue(obj, field, encryptedValue);	
		}

	}
	
	@Override
	protected void decryptSingle(Object obj) throws DecryptException{
		Assert.notNull(obj);
		
		Class<?> clazz = obj.getClass();
		List<Field> securityFields = processSecurityAnnotation(clazz);
		for(Field field: securityFields){
			ISecurityStrategy strategy = fieldSecurityStrategyMap.get(field);
			Object value = getFieldValue(obj, field);
			Object decryptedValue = null;
			if(value!=null && value instanceof String){
				decryptedValue = strategy.decrypt((String)value);
			}
			setFieldValue(obj, field, decryptedValue);
		}

	}
	

}
