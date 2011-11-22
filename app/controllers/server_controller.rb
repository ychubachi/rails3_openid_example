require 'pathname' # TODO: is this neccesary?
require "openid"
require "openid/consumer/discovery"
require 'openid/extensions/sreg'
require 'openid/extensions/pape'
require 'openid/store/filesystem'

Rails.logger.level = 0

class ServerController < ApplicationController
  include ServerHelper
  include OpenID::Server
  layout nil

# **************************************************************** begin XRDS  
  public

  # get /user/:username/
  def user_page
    # Yadis content-negotiation: we want to return the xrds if asked for.
    accept = request.env['HTTP_ACCEPT']

    # This is not technically correct, and should eventually be updated
    # to do real Accept header parsing and logic.  Though I expect it will work
    # 99% of the time.
    if accept and accept.include?('application/xrds+xml')
      user_xrds
    else
      render_html
    end
  end

  # get user/:username/xrds
  def user_xrds
    types = [
             OpenID::OPENID_2_0_TYPE,
             OpenID::OPENID_1_0_TYPE,
             OpenID::SREG_URI,
            ]
    render_xrds(types)
  end

  # get server/xrds
  def idp_xrds
    types = [
             OpenID::OPENID_IDP_2_0_TYPE,
            ]
    render_xrds(types)
  end

  private

  def render_xrds(types)
    @types = types
    render :action => 'yadis', :content_type => 'application/xrds+xml', :format => 'xml'
  end

  def render_html
    @xrds_url = "/user/#{params[:username]}/xrds" # TODO: Can't we use url_for?
    response.headers['X-XRDS-Location'] = @xrds_url
    render :action => 'xrds'
  end
# **************************************************************** end XRDS

# **************************************************************** begin Index
  public

  def index
    oidreq = server.decode_request(params) # throws ProtocolError if the OpenID request is invalid.
    raise "This is an OpenID server endpoint." unless oidreq # TODO: is this necessary?

    oidresp = nil
    if oidreq.kind_of?(CheckIDRequest)
      identity = oidreq.identity
      if oidreq.id_select
        if oidreq.immediate
          oidresp = oidreq.answer(false)
        elsif session[:username].nil?
          # The user hasn't logged in.
          show_decision_page(oidreq)
          return
        else
          # Else, set the identity to the one the user is using.
          identity = url_for_user
        end
      end

      if oidresp
        nil
      elsif self.is_authorized(identity, oidreq.trust_root)
        oidresp = oidreq.answer(true, nil, identity)

        # add the sreg response if requested
        add_sreg(oidreq, oidresp)
        # ditto pape
        add_pape(oidreq, oidresp)

      elsif oidreq.immediate
        server_url = url_for :action => 'index'
        oidresp = oidreq.answer(false, server_url)

      else
        show_decision_page(oidreq)
        return
      end

    else
      oidresp = server.handle_request(oidreq)
    end

    self.render_response(oidresp)

  rescue ProtocolError => e
    # invalid openid request, so just display a page with an error message
    logger.debug 'ProtocolError:' + e.to_s
    render :text => e.to_s, :status => 500
  end

  private

  def show_decision_page(oidreq, message="Do you trust this site with your identity?")
    session[:last_oidreq] = oidreq
    @oidreq = oidreq

    if message
      flash[:notice] = message
    end

    render :template => 'server/decide', :layout => 'server'
  end

  protected # TODO: Why 'protected'?

  def is_authorized(identity_url, trust_root)
    return (session[:username] and (identity_url == url_for_user) and self.approved(trust_root))
  end
# **************************************************************** end Index

# **************************************************************** begin Decision
  public

  def decision
    oidreq = session[:last_oidreq]
    session[:last_oidreq] = nil

    if params[:yes].nil?
      redirect_to oidreq.cancel_url
    else
      id_to_send = params[:id_to_send]

      identity = oidreq.identity
      if oidreq.id_select
        if id_to_send and id_to_send != ""
          session[:username] = id_to_send
          session[:approvals] = []
          identity = url_for_user
        else
          msg = "You must enter a username to in order to send " +
            "an identifier to the Relying Party."
          show_decision_page(oidreq, msg)
          return
        end
      end

      if session[:approvals]
        session[:approvals] << oidreq.trust_root
      else
        session[:approvals] = [oidreq.trust_root]
      end
      oidresp = oidreq.answer(true, nil, identity)
      add_sreg(oidreq, oidresp)
      add_pape(oidreq, oidresp)
      return self.render_response(oidresp)
    end
  end

  private

  def add_sreg(oidreq, oidresp)
    # check for Simple Registration arguments and respond
    sregreq = OpenID::SReg::Request.from_openid_request(oidreq)

    return if sregreq.nil?
    # In a real application, this data would be user-specific,
    # and the user should be asked for permission to release
    # it.
    sreg_data = {
      'nickname' => session[:username],
      'fullname' => 'Mayor McCheese',
      'email' => 'mayor@example.com'
    }

    sregresp = OpenID::SReg::Response.extract_response(sregreq, sreg_data)
    oidresp.add_extension(sregresp)
  end

  def add_pape(oidreq, oidresp)
    papereq = OpenID::PAPE::Request.from_openid_request(oidreq)
    return if papereq.nil?
    paperesp = OpenID::PAPE::Response.new
    paperesp.nist_auth_level = 0 # we don't even do auth at all!
    oidresp.add_extension(paperesp)
  end

  protected # TODO: Why?

  def render_response(oidresp)
    if oidresp.needs_signing # TODO: Necessary?
      signed_response = server.signatory.sign(oidresp)
    end

    web_response = server.encode_response(oidresp)
    case web_response.code
    when HTTP_OK
      render :text => web_response.body, :status => 200
    when HTTP_REDIRECT
      redirect_to web_response.headers['location']
    else
      render :text => web_response.body, :status => 400
    end
  end
# **************************************************************** end Decision

# **************************************************************** shared methods
  private

  def server
    if @server.nil?
      server_url = url_for :action => 'index', :only_path => false
      dir = Pathname.new(Rails.root).join('db').join('openid-store')
      store = OpenID::Store::Filesystem.new(dir)
      @server = Server.new(store, server_url)
    end
    return @server
  end
end
