package ca.uhn.fhir.jpa.starter;

import org.hl7.fhir.instance.model.api.IBaseResource;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;

@Interceptor
public class YourInterceptor
{
    @Hook(Pointcut.STORAGE_PRECOMMIT_RESOURCE_CREATED)
    public void resourceCreated(IBaseResource newResource)
    {
        System.out.println("Recurso creado: " + newResource.getIdElement().getValue());
    }
}