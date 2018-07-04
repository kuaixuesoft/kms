package com.tuniu.finance.xff.auth.security;

import java.beans.PropertyDescriptor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class AbstractBeanSecurityHelper {
	protected Map<Class<?>, List<Field>> securityFields = new HashMap<Class<?>, List<Field>>();
	protected ISecurityStrategy defaultSecurityStrategy;
	protected Map<String, ISecurityStrategy> securityStrategies = new HashMap<String, ISecurityStrategy>();
	protected Map<Field, ISecurityStrategy> fieldSecurityStrategyMap = new HashMap<Field, ISecurityStrategy>();
	
	protected Object getFieldValue(Object obj, Field field){
		try{
			PropertyDescriptor pd = new PropertyDescriptor(field.getName(), obj.getClass());
			return pd.getReadMethod().invoke(obj);
		}
		catch(Exception e){
			throw new RuntimeException("failed to get field value:"+obj.getClass().getName()+"."+field.getName(), e);
		}
	}
	
	protected void setFieldValue(Object obj, Field field, Object value){
		try{
			PropertyDescriptor pd = new PropertyDescriptor(field.getName(), obj.getClass());
			pd.getWriteMethod().invoke(obj, value);
		}
		catch(Exception e){
			throw new RuntimeException("failed to set field value:"+obj.getClass().getName()+"."+field.getName(), e);
		}
	}
	
	protected List<Field> processSecurityAnnotation(Class<?> clazz){
		if(securityFields.containsKey(clazz)==false){
			List<Field> fields = new ArrayList<Field>();
			for(Field field: clazz.getDeclaredFields()){
				Security security = field.getAnnotation(Security.class);
				if(security!=null){
					String securityValue = security.value();
					ISecurityStrategy securityStrategy = null;
					if(securityValue.isEmpty()){
						securityStrategy = defaultSecurityStrategy;
					}
					else{
						securityStrategy = securityStrategies.get(securityValue);
						if(securityStrategy==null){
							throw new IllegalArgumentException("no security strategy names: "+securityValue);
						}
					}					
					fieldSecurityStrategyMap.put(field, securityStrategy);
					fields.add(field);					
				}
			}
			securityFields.put(clazz, fields);
		}
		return securityFields.get(clazz);
	}
	
	protected abstract void encryptSingle(Object obj) throws EncryptException;
	protected abstract void decryptSingle(Object obj) throws DecryptException;		
	
	public void setDefaultSecurityStrategy(ISecurityStrategy defaultSecurityStrategy){
		this.defaultSecurityStrategy = defaultSecurityStrategy;	
	}
	
	public void setSecurityStrategies(Map<String, ISecurityStrategy> securityStrategies){
		this.securityStrategies = securityStrategies;	
	}
	
	@SuppressWarnings("unchecked")
	public <T> T encrypt(T obj)  throws EncryptException{		
		if(obj==null) return obj;
		
		Class<T> clazz = (Class<T>)obj.getClass();				
		
		/*如果是map，不做处理*/
		if(Map.class.isAssignableFrom(clazz)){
			return obj;
		}
		
		if(Collection.class.isAssignableFrom(clazz)){
			for(Object o: (Collection<?>)obj){
				encryptSingle(o);
			}
		}
		else{
			encryptSingle(obj);
		}
		return obj;
	}
	
	@SuppressWarnings("unchecked")
	public <T> T decrypt(T obj) throws DecryptException{
		if(obj==null) return obj;
		
		Class<T> clazz = (Class<T>)obj.getClass();

		if(Collection.class.isAssignableFrom(clazz)){
			for(Object o: (Collection<?>)obj){
				decryptSingle(o);
			}
		}
		else{
			decryptSingle(obj);
		}
		return obj;

	}
}
