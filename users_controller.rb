class UsersController < ApplicationController

  require 'net/http'

  before_action :login_required, :only=>['change_password', 'show', 'index', 'hidden']
  http_basic_authenticate_with :name => "admin", :password => "#{ADMPW}", :only => [:index, :destroy, :delete]

  attr_accessor :id
  attr_accessor :login
  attr_accessor :email
  attr_accessor :hashed_password
  attr_accessor :salt

  #def initialize(id,login,password,email)
  #  @id = id
  #  @login = login
  #  @password = password
  #  @email = email
  #end

  def user_params
     params.require(:user).permit(:login, :email, :hashed_password, :password_confirmation)
  end

  def signup
    flash[:error] = ""
    @user = User.new
    respond_to do |format|
      format.html
      format.xml  { render :xml => @user }
    end
  end

  def login
    if request.post?
      if session[:user] = User.authenticate(params[:user][:login], params[:user][:password])
        flash[:message]  = "Login successful"
	@error = ""
	redirect_to :controller=>'study_groups', :action=>'get_user_groups'
	return
      else
        Rails.logger.debug "Login unsuccessful"
	User.errors.add_to_base("Login unsuccessful") if :login.blank?
	@error = "Login unsuccessful. Please check username and password. "
	flash[:error] = @error
      end
    else
      flash[:error] = ""
    end
    respond_to do |format|
      format.html 
      format.xml  { render :xml => @user }
    end
	
  end

  def logout
    reset_session
    flash[:message] = 'Logged out'
    #flash[:notice] = "Please login to continue"
    redirect_to :action => 'login'
  end
  
  def reset
    @user = User.find_by_reset_code(params[:reset_code]) unless params[:reset_code].nil?
    if @user.nil? then
      redirect_to 'users#signup'
    else
      if request.post? then
        if @user.update_attributes(:password => params[:user][:hashed_password], :password_confirmation => params[:user][:password_confirmation]) then
          @user.delete_reset_code
          flash[:notice] = "Password reset successfully. Please login to continue."
	  Rails.logger.debug "Password reset successfully"
          redirect_to root_url
        else
	  flash[:notice] = 'Password not updated.'
	  Rails.logger.debug "Password not updated"
          render :action => :reset
        end
      end
    end
  end

  def change_password
    @user = current_user #User.find_by_id(current_user.id) unless current_user.nil?
    if @user.nil? then
      redirect_to 'users#signup'
    else
      if request.post? then
        if @user.update_attributes(:password => params[:user][:hashed_password], :password_confirmation => params[:user][:password_confirmation]) then
          flash[:notice] = "Password changed successfully. Please login to continue."
	  Rails.logger.debug "Password changed successfully."
	  logout
          #redirect_to root_url
        else
          flash[:notice] = 'Password not updated.'
	  Rails.logger.debug "Password not updated"
          render :action => :login
        end
      end
    end
  end
  
  def forgot_password
    Rails.logger.debug "In Forgot Password"
    if request.post?
      Rails.logger.debug "Forgot Password. Email: " + params[:user][:email].to_s
      @user=User.find_by_email(params[:user][:email])  
      if @user.nil?
	flash[:notice] = 'User not found'
      else
        if @user.create_reset_code
	  UserMailer.reset_notification(@user).deliver_now!
	  flash[:notice] = "A link to reset the password has been sent by email."
	  Rails.logger.debug "User notification delivered : " + @user.reset_code
	  redirect_to root_url #:action=>'login'
	  return
	else
	  flash[:notice] = "reset code not generated"
	  Rails.logger.debug "Error generating reset code" 
	end
      end
    end
    respond_to do |format|
      format.html
      format.xml { render :xml => @user }
    end	
  end	
 
  def load_user
    session[:user] = User.find_by_login(params[:user][:login])
    params[:id] = session[:user][:id]
    return session[:user]
  end 
  
  def update
    @user = User.find(params[:id])

    respond_to do |format|
      if @user.update_attributes(params[:user])
	Rails.logger.debug "User successfully updated."
        flash[:notice] = 'User was successfully updated.'
	#UserMailer.deliver_user_details(@user.email, @user.login, @user.password, @user, Time.now)
        format.html { redirect_to(@user) }
        format.xml  { head :ok }
      else
	Rails.logger.debug "Error updating user."
        format.html # { render :action => "edit" }
      #  format.xml  { render :xml => @user.errors, :status => :unprocessable_entity }
      end
    end
  end	  

  
  #def delete
  #  @user = User.find(params[:id])
  #  @user.destroy
  #  flash[:notice] = 'User was successfully deleted.' 
  #  respond_to do |format|
  #    format.html {  render :action => "login" } 
  #    format.xml  { head :ok }
  #  end 
  #end
  
  def destroy
    begin	
      @user = User.find(params[:id])
      @user.destroy
      logout
    rescue => e
      @error = "Redirecting.."
      Rails.logger.debug "Error while deleting user: " + e.message.to_s
    end
  end
  
  
  def contact_form
    if request.post?
      begin
        UserMailer.user_message(params[:contact][:email], "#{EMAIL_USER}", params[:contact][:incoming_message], 'New message received').deliver_now!
        flash[:notice] = "Delivered message by #{params[:contact][:email]} to #{EMAIL_USER}"
      rescue => e
	flash[:error] = "Error while delivering message. Please try again."
      end	
    else
	flash[:notice] = ""
    end
    respond_to do |format|
      format.html 
      format.xml 
    end
  end
  

  def edit
  
  end
  
  def show
    begin
      load_user if params[:id].nil?
      @user = User.find(params[:id])
      respond_to do |format|
      	format.html # show.html.erb
      	format.xml  { render :xml => @user }
      end
    rescue
      @error = "User not found"
      Rails.logger.debug "User not found"
    end
  end
  

  def index
    @user = User.all

    respond_to do |format|
      format.html # index.html.erb
      format.xml  { render :xml => @user }
    end
  end
  
  def create
    @user = User.new(user_params)	
    @existinguser = User.find_by_email(@user.email)
    if !@existinguser.nil? 
	flash[:error] = "User already exists."
	#redirect_to root_url
	render :action => :signup
	return
    end
    @user.password = @user.hashed_password
    respond_to do |format|
      	
      encrypt(@user.hashed_password, @user.salt)
      if @user.save
	Rails.logger.debug "New user created."
        session[:user] = User.authenticate(@user.login, @user.hashed_password)
        flash[:notice] = 'User was successfully created. Please login to continue'
	begin
	  UserMailer.welcome_email(@user).deliver
	  Rails.logger.debug "Welcome email delivered"
        rescue SocketError => e
          Rails.logger.debug "SocketErrorMessage: " + e.message.to_s
	  flash[:error] = "There was a socket error while delivering confirmation email for user " + @user.login
	rescue Net::SMTPAuthenticationError, Net::SMTPServerBusy, Net::SMTPSyntaxError, Net::SMTPFatalError, Net::SMTPUnknownError, Net::OpenTimeout => e
 	  Rails.logger.debug "Error in create: " + e.message.to_s
	  flash[:error] = "User " + @user.login + " created. However, there was a problem delivering email confirmation. " + e.message.to_s
        end
        #@error = "Please login to continue"
	#flash[:error] = @error
	flash[:notice] = 'User was successfully created. Please login to continue'
        format.html { logout }
      else
	flash[:error] = "User not saved. Please check your details and try again."
        format.html { render :action => "signup" }
      end
    end
  end


  def encrypt(pass, salt)
    Digest::SHA1.hexdigest(pass+salt)
  end

end
