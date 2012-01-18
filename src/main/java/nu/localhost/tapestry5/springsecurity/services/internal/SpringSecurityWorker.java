/*
 * Copyright 2007 Ivan Dubrov
 * Copyright 2007, 2008 Robin Helgelin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nu.localhost.tapestry5.springsecurity.services.internal;

import java.util.ArrayList;
import java.util.List;

import org.apache.tapestry5.annotations.BeginRender;
import org.apache.tapestry5.annotations.CleanupRender;
import org.apache.tapestry5.model.MutableComponentModel;
import org.apache.tapestry5.plastic.FieldHandle;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.apache.tapestry5.plastic.PlasticClass;
import org.apache.tapestry5.plastic.PlasticField;
import org.apache.tapestry5.plastic.PlasticMethod;
import org.apache.tapestry5.services.TransformConstants;
import org.apache.tapestry5.services.transform.ComponentClassTransformWorker2;
import org.apache.tapestry5.services.transform.TransformationSupport;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.intercept.InterceptorStatusToken;

/**
 * @author Ivan Dubrov
 */
public class SpringSecurityWorker implements ComponentClassTransformWorker2 {

    private SecurityChecker securityChecker;

    public SpringSecurityWorker(final SecurityChecker securityChecker) {

        this.securityChecker = securityChecker;
    }

    public final void transform(PlasticClass plasticClass, TransformationSupport support, MutableComponentModel model)
    {
        model.addRenderPhase(BeginRender.class);
        model.addRenderPhase(CleanupRender.class);

        // Secure methods
        for (PlasticMethod method : plasticClass.getMethodsWithAnnotation(Secured.class)) {
            transformMethod(plasticClass, method);
        }

        // Secure pages
        Secured annotation = plasticClass.getAnnotation(Secured.class);
        if (annotation != null) {
            transformPage(plasticClass, annotation);
        }
    }

    private void transformPage(final PlasticClass plasticClass, final Secured annotation) {

        // Security checker

        final PlasticField interField = plasticClass.introduceField(SecurityChecker.class, "_$checker");
        interField.inject(securityChecker);

        final ConfigAttributeHolder confAttrHolder = createConfigAttributeDefinitionField(plasticClass, annotation);

        PlasticField tokenFieldInstance = plasticClass.introduceField(
                                                                       org.springframework.security.access.intercept.InterceptorStatusToken.class,
                                                                       "_$token"); // InterceptorStatusToken

        final FieldHandle tokenFieldAccess = tokenFieldInstance.getHandle();

        adviseBeginRender(plasticClass, confAttrHolder, tokenFieldAccess, securityChecker);

        adviseCleanupRender(plasticClass, tokenFieldAccess, securityChecker);

        //adviseEventMethods(plasticClass, confAttrHolder, securityChecker);

    }

    private void adviseBeginRender(PlasticClass plasticClass, final ConfigAttributeHolder confAttrHolder,
        final FieldHandle tokenFieldAccess, final SecurityChecker secChecker) {
        
        PlasticMethod beginRenderMethod = plasticClass.introduceMethod(TransformConstants2.BEGIN_RENDER_DESCRIPTION);

        MethodAdvice beginRenderAdvice = new MethodAdvice() {

            public void advise(MethodInvocation invocation) {
                invocation.proceed();

                InterceptorStatusToken statusTokenVal = secChecker.checkBefore(confAttrHolder);
                tokenFieldAccess.set(invocation.getInstance(), statusTokenVal);
            }
        };
        
        beginRenderMethod.addAdvice(beginRenderAdvice);
    }
    
    private void adviseCleanupRender(PlasticClass plasticClass, final FieldHandle tokenFieldAccess,
                                   final SecurityChecker secChecker) {
        PlasticMethod cleanupRenderMethod =
                plasticClass.introduceMethod(TransformConstants2.CLEANUP_RENDER_DESCRIPTION);

        MethodAdvice cleanupRenderAdvice = new MethodAdvice() {
    
            public void advise(MethodInvocation invocation) {
                invocation.proceed();
    
                InterceptorStatusToken tokenFieldValue =
                        (InterceptorStatusToken) tokenFieldAccess.get(invocation.getInstance());
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };
    
        cleanupRenderMethod.addAdvice(cleanupRenderAdvice);
    }

    private void adviseEventMethods(PlasticClass plasticClass, final ConfigAttributeHolder confAttrHolder,
        final SecurityChecker secChecker) {
      MethodAdvice eventAdvice = new MethodAdvice() {

            public void advise(MethodInvocation invocation) {
                InterceptorStatusToken tokenFieldValue = secChecker.checkBefore(confAttrHolder);
                invocation.proceed();
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };
        plasticClass.introduceMethod(TransformConstants.DISPATCH_COMPONENT_EVENT_DESCRIPTION).addAdvice(eventAdvice);
    }

    private void transformMethod(final PlasticClass plasticClass, final PlasticMethod securedMethod) {
        // Security checker
        final PlasticField interField = plasticClass.introduceField(SecurityChecker.class, "_$checker");
        interField.inject(securityChecker);

        PlasticField tokenFieldInstance = plasticClass.introduceField(
              org.springframework.security.access.intercept.InterceptorStatusToken.class,
              "_$token"); // InterceptorStatusToken

        final FieldHandle tokenFieldAccess = tokenFieldInstance.getHandle();

        // Attribute definition
        final Secured annotation = securedMethod.getAnnotation(Secured.class);
        final ConfigAttributeHolder confAttrHolder = createConfigAttributeDefinitionField(plasticClass, annotation);

        // Prefix and extend method
        final SecurityChecker secChecker = this.securityChecker;
        MethodAdvice securedMethodAdvice = new MethodAdvice() {

            public void advise(MethodInvocation invocation) {
                InterceptorStatusToken statusTokenVal = secChecker.checkBefore(confAttrHolder);
                tokenFieldAccess.set(invocation.getInstance(), statusTokenVal);
                
                invocation.proceed();

                InterceptorStatusToken tokenFieldValue = (InterceptorStatusToken) tokenFieldAccess.get(invocation.getInstance());
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };

        securedMethod.addAdvice(securedMethodAdvice);
    }

    private ConfigAttributeHolder createConfigAttributeDefinitionField(
            final PlasticClass plasticClass,
            final Secured annotation) {

        List<ConfigAttribute> configAttributeDefinition = new ArrayList<ConfigAttribute>();
        for (String annValue : annotation.value()) {
            configAttributeDefinition.add(new SecurityConfig(annValue));
        }
        ConfigAttributeHolder configAttributeHolder = new ConfigAttributeHolder(configAttributeDefinition);
        plasticClass
          .introduceField(ConfigAttributeHolder.class, "_$configAttributeDefinition")
          .inject(configAttributeHolder);
        return configAttributeHolder;
    }
}
