package com.mirth.connect.client.core.api.providers;

import javax.ws.rs.ext.*;
import javax.inject.*;
import java.lang.annotation.*;
import javax.ws.rs.core.*;
import java.util.*;
import java.lang.reflect.*;
import org.apache.commons.lang3.*;
import com.mirth.connect.model.converters.*;
import org.apache.commons.io.*;
import java.io.*;
import javax.ws.rs.*;
import com.fasterxml.jackson.databind.*;

@Provider
@Singleton
@Consumes({ "application/xml" })
public class XmlMessageBodyReader implements MessageBodyReader<Object>
{
    private final ObjectMapper objectMapper;

    public XmlMessageBodyReader() {
        super();
        this.objectMapper = new ObjectMapper();
    }

    public boolean isReadable(final Class<?> type, final Type genericType, final Annotation[] annotations, final MediaType mediaType) {
        return true;
    }

    public Object readFrom(final Class<Object> type, final Type genericType, final Annotation[] annotations, final MediaType mediaType, final MultivaluedMap<String, String> httpHeaders, final InputStream entityStream) throws IOException, WebApplicationException {
        if (type.equals(List.class) && genericType instanceof ParameterizedType) {
            final Type[] actualTypes = ((ParameterizedType)genericType).getActualTypeArguments();
            if (ArrayUtils.isNotEmpty(actualTypes) && actualTypes[0] instanceof Class) {
                return this.objectMapper.readValue(entityStream, this.objectMapper.getTypeFactory().constructCollectionType(List.class, (Class<?>) actualTypes[0]));
            }
        }
        return this.objectMapper.readValue(entityStream, type);
    }
}