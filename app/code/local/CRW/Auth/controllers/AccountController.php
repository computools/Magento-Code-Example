<?php
require_once("Mage/Customer/controllers/AccountController.php");

/**
 * Customer account controller
 */
 class CRW_Auth_AccountController extends Mage_Customer_AccountController
 {
    // Check user is in Unapproved grousp
    public function is_user_approved() {
        // Check Customer is loggedin or not
        if(Mage::getSingleton('customer/session')->isLoggedIn()){
            // Get group Id
            $groupId = Mage::getSingleton('customer/session')->getCustomerGroupId();
            //Get customer Group name
            $group = Mage::getModel('customer/group')->load($groupId);
            // Check approved
            if($group->getCode() == 'Unapproved')
                // User is unapproved
                return false;
            else 
                // User is approved now
                return true;
        }
        else {
            // User is unapproved
            return false;
        }
    }

	/**
    * Customer login form page
    */
	public function indexAction()
	{
        if($this->is_user_approved()) {
            $this->getResponse()->setHeader('Login-Required', 'true');
            $this->loadLayout();
            $this->_initLayoutMessages('customer/session');
            $this->_initLayoutMessages('catalog/session');
            $this->renderLayout();
        }
        else {
            $session->addError($this->__('You must be an approved user'));
            $this->logoutAction();
        }
	}

	/**
     * Login post action
     */
    public function loginPostAction()
    {
        if (!$this->_validateFormKey()) {
            $this->_redirect('*/*/');
            return;
        }

        if ($this->_getSession()->isLoggedIn()) {
            $this->_redirect('*/*/');
            return;
        }
        $session = $this->_getSession();

        if ($this->getRequest()->isPost()) {
            $login = $this->getRequest()->getPost('login');
            if (!empty($login['username']) && !empty($login['password'])) {
                try {
                    $session->login($login['username'], $login['password']);
                    if ($session->getCustomer()->getIsJustConfirmed()) {
                        $this->_welcomeCustomer($session->getCustomer(), true);
                    }
                } catch (Mage_Core_Exception $e) {
                    switch ($e->getCode()) {
                        case Mage_Customer_Model_Customer::EXCEPTION_EMAIL_NOT_CONFIRMED:
                            $value = $this->_getHelper('customer')->getEmailConfirmationUrl($login['username']);
                            $message = $this->_getHelper('customer')->__('This account is not confirmed. <a href="%s">Click here</a> to resend confirmation email.', $value);
                            break;
                        case Mage_Customer_Model_Customer::EXCEPTION_INVALID_EMAIL_OR_PASSWORD:
                            $message = $e->getMessage();
                            break;
                        default:
                            $message = $e->getMessage();
                    }
                    $session->addError($message);
                    $session->setUsername($login['username']);
                } catch (Exception $e) {
                    // Mage::logException($e); // PA DSS violation: this exception log can disclose customer password
                }
            } else {
                $session->addError($this->__('Login and password are required.'));
            }
        }
        // Check if customer is an approved
        if($this->is_user_approved()) {
        	$this->_loginPostRedirect();
        }
        else {
            $session->addError($this->__('You must be an approved user'));
            $this->logoutAction();
        }
    }

     /**
     * Create customer account action
     */
    public function createPostAction()
    {
        /** @var $session Mage_Customer_Model_Session */
        $session = $this->_getSession();
        if ($session->isLoggedIn()) {
            $this->_redirect('*/*/');
            return;
        }
        $session->setEscapeMessages(true); // prevent XSS injection in user input
        if (!$this->getRequest()->isPost()) {
            $errUrl = $this->_getUrl('*/*/create', array('_secure' => true));
            $this->_redirectError($errUrl);
            return;
        }

        $customer = $this->_getCustomer();

        try {
            $errors = $this->_getCustomerErrors($customer);
            // Check if customer is an approved
            if($this->is_user_approved()) {
                $this->_loginPostRedirect();
            }
            else {
                $session->addError($this->__('You must be an approved user'));
                
            }

            if (empty($errors)) {
                $customer->cleanPasswordsValidationData();
                $customer->save();
                $this->_dispatchRegisterSuccess($customer);
                $this->_successProcessRegistration($customer);
                $this->logoutAction();
                return;
            } else {
                $this->_addSessionError($errors);
            }
        } catch (Mage_Core_Exception $e) {
            $session->setCustomerFormData($this->getRequest()->getPost());
            if ($e->getCode() === Mage_Customer_Model_Customer::EXCEPTION_EMAIL_EXISTS) {
                $url = $this->_getUrl('customer/account/forgotpassword');
                $message = $this->__('There is already an account with this email address. If you are sure that it is your email address, <a href="%s">click here</a> to get your password and access your account.', $url);
                $session->setEscapeMessages(false);
            } else {
                $message = $e->getMessage();
            }
            $session->addError($message);
        } catch (Exception $e) {
            $session->setCustomerFormData($this->getRequest()->getPost())
                ->addException($e, $this->__('Cannot save the customer.'));
        }
        $errUrl = $this->_getUrl('*/*/create', array('_secure' => true));
        $this->_redirectError($errUrl);
    }

 }
?>