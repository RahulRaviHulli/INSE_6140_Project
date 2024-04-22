package com.mirth.connect.server.api;

import javax.ws.rs.container.*;
import com.mirth.connect.server.controllers.*;
import org.apache.commons.lang3.*;
import org.apache.commons.codec.binary.*;
import javax.ws.rs.core.*;
import com.mirth.connect.client.core.api.*;
import com.mirth.connect.client.core.*;
import javax.servlet.http.*;
import java.util.*;
import com.mirth.connect.model.*;
import java.net.*;

public abstract class MirthServlet
{
    public static final String BYPASS_USERNAME = "bypass";
    protected static final String SESSION_USER = "user";
    protected static final String SESSION_AUTHORIZED = "authorized";
    protected HttpServletRequest request;
    protected ContainerRequestContext containerRequestContext;
    protected SecurityContext sc;
    protected ServerEventContext context;
    protected Operation operation;
    protected Map<String, Object> parameterMap;
    private boolean channelRestrictionsInitialized;
    private boolean userHasChannelRestrictions;
    private ChannelAuthorizer channelAuthorizer;
    protected ControllerFactory controllerFactory;
    private static UserController userController;
    private static AuthorizationController authorizationController;
    private static ConfigurationController configurationController;
    private String extensionName;
    private boolean bypassUser;
    private int currentUserId;
    
    public MirthServlet(final HttpServletRequest request, final SecurityContext sc) {
        this(request, null, sc);
    }
    
    public MirthServlet(final HttpServletRequest request, final SecurityContext sc, final ControllerFactory controllerFactory) {
        this(request, null, sc, controllerFactory);
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc) {
        this(request, containerRequestContext, sc, true);
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc, final ControllerFactory controllerFactory) {
        this(request, containerRequestContext, sc, true, controllerFactory);
    }
    
    public MirthServlet(final HttpServletRequest request, final SecurityContext sc, final boolean initLogin) {
        this(request, null, sc, initLogin);
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc, final boolean initLogin) {
        this(request, containerRequestContext, sc, null, initLogin);
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc, final boolean initLogin, final ControllerFactory controllerFactory) {
        this(request, containerRequestContext, sc, null, initLogin, controllerFactory);
    }
    
    public MirthServlet(final HttpServletRequest request, final SecurityContext sc, final String extensionName) {
        this(request, null, sc, extensionName);
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc, final String extensionName) {
        this(request, containerRequestContext, sc, extensionName, true);
    }
    
    public MirthServlet(final HttpServletRequest request, final SecurityContext sc, final String extensionName, final boolean initLogin) {
        this(request, null, sc, extensionName, initLogin);
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc, final String extensionName, final boolean initLogin) {
        this(request, containerRequestContext, sc, extensionName, initLogin, ControllerFactory.getFactory());
    }
    
    public MirthServlet(final HttpServletRequest request, final ContainerRequestContext containerRequestContext, final SecurityContext sc, final String extensionName, final boolean initLogin, final ControllerFactory controllerFactory) {
        super();
        this.controllerFactory = controllerFactory;
        this.initializeControllers();
        this.request = request;
        this.containerRequestContext = containerRequestContext;
        this.sc = sc;
        this.extensionName = extensionName;
        this.parameterMap = new HashMap<String, Object>();
        if (initLogin) {
            this.initLogin();
        }
    }
    
    protected void initializeControllers() {
        MirthServlet.userController = this.controllerFactory.createUserController();
        MirthServlet.authorizationController = this.controllerFactory.createAuthorizationController();
        MirthServlet.configurationController = this.controllerFactory.createConfigurationController();
    }
    
    protected void initLogin() {
        boolean validLogin = false;
        if (this.isUserLoggedIn()) {
            this.currentUserId = Integer.parseInt(this.request.getSession().getAttribute("user").toString());
            this.setContext();
            validLogin = true;
        }
        else {
            String authHeader = this.request.getHeader("Authorization");
            if (StringUtils.startsWith(authHeader, "Basic ")) {
                String username = null;
                String password = null;
                try {
                    authHeader = new String(Base64.decodeBase64(StringUtils.removeStartIgnoreCase(authHeader, "Basic ").trim()), "US-ASCII");
                    final int colonIndex = StringUtils.indexOf(authHeader, 58);
                    if (colonIndex > 0) {
                        username = StringUtils.substring(authHeader, 0, colonIndex);
                        password = StringUtils.substring(authHeader, colonIndex + 1);
                    }
                }
                catch (Exception ex) {}
                if (username != null && password != null) {
                    if (StringUtils.equals(username, "bypass")) {
                        if (MirthServlet.configurationController.isBypasswordEnabled() && this.isRequestLocal() && MirthServlet.configurationController.checkBypassword(password)) {
                            this.context = ServerEventContext.SYSTEM_USER_EVENT_CONTEXT;
                            this.currentUserId = this.context.getUserId();
                            this.bypassUser = true;
                            validLogin = true;
                        }
                    }
                    else {
                        try {
                            final int status = MirthServlet.configurationController.getStatus(false);
                            if (status != 3 && status != 0) {
                                final LoginStatus loginStatus = new LoginStatus(LoginStatus.Status.FAIL, "Server is still starting or otherwise unavailable. Please try again shortly.");
                                throw new MirthApiException(Response.status(Response.Status.SERVICE_UNAVAILABLE).entity((Object)loginStatus).build());
                            }
                            LoginStatus loginStatus = MirthServlet.userController.authorizeUser(username, password);
                            if (loginStatus.getStatus() != LoginStatus.Status.SUCCESS && loginStatus.getStatus() != LoginStatus.Status.SUCCESS_GRACE_PERIOD) {
                                throw new MirthApiException(Response.status(Response.Status.UNAUTHORIZED).entity((Object)loginStatus).build());
                            }
                            final User user = MirthServlet.userController.getUser((Integer)null, username);
                            if (user == null) {
                                loginStatus = new LoginStatus(LoginStatus.Status.FAIL, "Could not find a valid user with username: " + username);
                                throw new MirthApiException(Response.status(Response.Status.UNAUTHORIZED).entity((Object)loginStatus).build());
                            }
                            this.currentUserId = user.getId();
                            this.setContext();
                            validLogin = true;
                        }
                        catch (ControllerException e) {
                            throw new MirthApiException((Throwable)e);
                        }
                    }
                }
            }
        }
        if (!validLogin) {
            throw new MirthApiException(Response.Status.UNAUTHORIZED);
        }
    }
    
    private void setContext() {
        this.context = new ServerEventContext(Integer.valueOf(this.currentUserId));
    }
    
    public void setOperation(Operation operation) {
        if (this.extensionName != null) {
            operation = (Operation)new ExtensionOperation(this.extensionName, operation);
        }
        this.operation = operation;
    }
    
    public void addToParameterMap(final String name, final Object value) {
        this.parameterMap.put(name, value);
    }
    
    protected String getSessionId() {
        return this.request.getSession().getId();
    }
    
    protected boolean isUserLoggedIn() {
        final HttpSession session = this.request.getSession();
        return session.getAttribute("authorized") != null && session.getAttribute("authorized").equals(true);
    }
    
    public void checkUserAuthorized() {
        if (!this.isUserAuthorized()) {
            throw new MirthApiException(Response.Status.FORBIDDEN);
        }
    }
    
    public void checkUserAuthorized(final Integer userId) {
        this.checkUserAuthorized(userId, true);
    }
    
    public void checkUserAuthorized(final Integer userId, final boolean auditCurrentUser) {
        if (auditCurrentUser) {
            if (!this.isUserAuthorized() && !this.isCurrentUser(userId)) {
                throw new MirthApiException(Response.Status.FORBIDDEN);
            }
        }
        else if (!this.isCurrentUser(userId) && !this.isUserAuthorized()) {
            throw new MirthApiException(Response.Status.FORBIDDEN);
        }
    }
    
    public void checkUserAuthorized(final String channelId) {
        if (!this.isUserAuthorized() || this.isChannelRedacted(channelId)) {
            throw new MirthApiException(Response.Status.FORBIDDEN);
        }
    }
    
    protected boolean isUserAuthorized() {
        return this.isUserAuthorized(true);
    }
    
    protected boolean isUserAuthorized(final boolean audit) {
        if (this.context == null) {
            this.initLogin();
        }
        if (this.operation == null) {
            throw new MirthApiException("Method operation not set.");
        }
        try {
            if (this.bypassUser) {
                if (audit) {
                    this.auditAuthorizationRequest(ServerEvent.Outcome.SUCCESS);
                }
                return true;
            }
            return MirthServlet.authorizationController.isUserAuthorized(Integer.valueOf(this.getCurrentUserId()), this.operation, (Map)this.parameterMap, this.getRequestIpAddress(), audit);
        }
        catch (ControllerException e) {
            throw new MirthApiException((Throwable)e);
        }
    }
    
    protected void checkUserAuthorizedForExtension(final String extensionName) {
        if (!this.isUserAuthorizedForExtension(extensionName)) {
            throw new MirthApiException(Response.Status.FORBIDDEN);
        }
    }
    
    protected boolean isUserAuthorizedForExtension(final String extensionName) {
        return this.isUserAuthorizedForExtension(extensionName, true);
    }
    
    protected boolean isUserAuthorizedForExtension(final String extensionName, final boolean audit) {
        if (this.operation == null) {
            throw new MirthApiException("Method operation not set.");
        }
        try {
            final ExtensionOperation extensionOperation = new ExtensionOperation(extensionName, this.operation);
            if (this.bypassUser) {
                if (audit) {
                    this.auditAuthorizationRequest(ServerEvent.Outcome.SUCCESS, (Operation)extensionOperation);
                }
                return true;
            }
            return MirthServlet.authorizationController.isUserAuthorized(Integer.valueOf(this.getCurrentUserId()), (Operation)extensionOperation, (Map)this.parameterMap, this.getRequestIpAddress(), audit);
        }
        catch (ControllerException e) {
            throw new MirthApiException((Throwable)e);
        }
    }
    
    protected void auditAuthorizationRequest(final ServerEvent.Outcome outcome) {
        this.auditAuthorizationRequest(outcome, this.operation);
    }
    
    protected void auditAuthorizationRequest(final ServerEvent.Outcome outcome, final Operation operation) {
        MirthServlet.authorizationController.auditAuthorizationRequest(Integer.valueOf(this.getCurrentUserId()), operation, (Map)this.parameterMap, outcome, this.getRequestIpAddress());
    }
    
    protected int getCurrentUserId() {
        return this.currentUserId;
    }
    
    protected String getRequestIpAddress() {
        String address = this.request.getHeader("x-forwarded-for");
        if (address == null) {
            address = this.request.getRemoteAddr();
        }
        return address;
    }
    
    protected List<Channel> redactChannels(final List<Channel> channels) {
        this.initChannelRestrictions();
        if (this.userHasChannelRestrictions) {
            final List<Channel> authorizedChannels = new ArrayList<Channel>();
            for (final Channel channel : channels) {
                if (this.channelAuthorizer.isChannelAuthorized(channel.getId())) {
                    authorizedChannels.add(channel);
                }
            }
            return authorizedChannels;
        }
        return channels;
    }
    
    protected Set<String> redactChannelIds(final Set<String> channelIds) {
        this.initChannelRestrictions();
        if (this.userHasChannelRestrictions) {
            final Set<String> finishedChannelIds = new HashSet<String>();
            for (final String channelId : channelIds) {
                if (this.channelAuthorizer.isChannelAuthorized(channelId)) {
                    finishedChannelIds.add(channelId);
                }
            }
            return finishedChannelIds;
        }
        return channelIds;
    }
    
    protected <T> Map<String, T> redactChannelIds(final Map<String, T> map) {
        this.initChannelRestrictions();
        if (this.userHasChannelRestrictions) {
            final Map<String, T> authorizedMap = new HashMap<String, T>();
            for (final Map.Entry<String, T> entry : map.entrySet()) {
                if (this.channelAuthorizer.isChannelAuthorized((String)entry.getKey())) {
                    authorizedMap.put(entry.getKey(), entry.getValue());
                }
            }
            return authorizedMap;
        }
        return map;
    }
    
    protected List<ChannelSummary> redactChannelSummaries(final List<ChannelSummary> channelSummaries) {
        this.initChannelRestrictions();
        if (this.userHasChannelRestrictions) {
            final List<ChannelSummary> authorizedChannelSummaries = new ArrayList<ChannelSummary>();
            for (final ChannelSummary channelSummary : channelSummaries) {
                if (this.channelAuthorizer.isChannelAuthorized(channelSummary.getChannelId())) {
                    authorizedChannelSummaries.add(channelSummary);
                }
            }
            return authorizedChannelSummaries;
        }
        return channelSummaries;
    }
    
    protected boolean doesUserHaveChannelRestrictions() {
        this.initChannelRestrictions();
        return this.userHasChannelRestrictions;
    }
    
    protected boolean isChannelRedacted(final String channelId) {
        this.initChannelRestrictions();
        return this.userHasChannelRestrictions && !this.channelAuthorizer.isChannelAuthorized(channelId);
    }
    
    protected ChannelAuthorizer getChannelAuthorizer() {
        return this.channelAuthorizer;
    }
    
    private void initChannelRestrictions() {
        if (!this.channelRestrictionsInitialized) {
            try {
                this.userHasChannelRestrictions = (!this.bypassUser && MirthServlet.authorizationController.doesUserHaveChannelRestrictions(Integer.valueOf(this.currentUserId), this.operation));
                if (this.userHasChannelRestrictions) {
                    this.channelAuthorizer = MirthServlet.authorizationController.getChannelAuthorizer(Integer.valueOf(this.currentUserId), this.operation);
                }
            }
            catch (ControllerException e) {
                throw new MirthApiException((Throwable)e);
            }
            this.channelRestrictionsInitialized = true;
        }
    }
    
    protected boolean isCurrentUser(final Integer userId) {
        return userId == this.getCurrentUserId();
    }
    
    protected boolean isRequestLocal() {
        final String remoteAddr = this.request.getRemoteAddr().replace("[", "").replace("]", "");
        try {
            if (StringUtils.equals(InetAddress.getLocalHost().getHostAddress(), remoteAddr)) {
                return true;
            }
        }
        catch (UnknownHostException ex) {}
        try {
            for (final InetAddress inetAddress : InetAddress.getAllByName("localhost")) {
                if (StringUtils.equals(inetAddress.getHostAddress(), remoteAddr)) {
                    return true;
                }
            }
        }
        catch (UnknownHostException ex2) {}
        return false;
    }
}

