/*
 * Copyright © 2017 Sana and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.Antivirus.impl;

import java.util.concurrent.Future;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.ReadOnlyTransaction;
import org.opendaylight.controller.md.sal.binding.api.ReadWriteTransaction;
import org.opendaylight.controller.md.sal.binding.api.WriteTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.controller.md.sal.common.api.data.ReadFailedException;
import org.opendaylight.controller.md.sal.common.api.data.TransactionCommitFailedException;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.AntivirusService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.ApplicationHelloInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.ApplicationHelloOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.ApplicationHelloOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.ConfigurationRulesRegistry;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.ConfigurationRulesRegistryBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.configurationrules.registry.ConfigurationRulesRegistryEntry;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.configurationrules.registry.ConfigurationRulesRegistryEntryBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.configurationrules.registry.ConfigurationRulesRegistryEntryKey;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.opendaylight.yangtools.yang.common.RpcResultBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.util.concurrent.CheckedFuture;
import com.google.common.util.concurrent.Futures;

public class AntivirusImpl implements AntivirusService {
	
	//TODO -- Handle exceptions everywhere in the code; special characters are problematic. (Fixed)
	//TODO -- Handle Rule Duplication for all three modes. 
	//TODO -- Handle Rule Conflict for all three modes. 
	
	private static final Logger LOG = LoggerFactory.getLogger(AntivirusImpl.class);
	private DataBroker db;

	/*---------- The following parameters are configured by Network Practitioner ----------*/
	/* (1) Total number of Applications that can access configuration datastore. There are typically 400 applications.*/
	int Number_of_Applications = 400;

	/* (2) The total capacity in configuration datastore.*/
	int C = 4000;
	
	/* (3) Password Dictionary. */
	// Use something like OTP or RSA...depending on which one is more efficient.
	String [] Password_Dictionary = new String [Number_of_Applications];
			                       
	/* (4) 	 */
	int TierOneApplications = 200;
	int TierTwoApplications = 100;
	int TierThreeApplications = 100;
	
	/* Operation Codes; 0 -- Add a New Rule, 1 -- Delete an existing Rule, Anything else -- Error */
	int operation;
	
	/*-------------------- Temporary Variables --------------------*/
	int [] App_Inventory = new int [Number_of_Applications];

	int current_AppID;
	String result;
	String Field;
		
	/* Threshold_Inventory specifies an upper limit on how many rules each application can store in configuration datastore. */
	int [] Threshold_Inventory = new int [Number_of_Applications];
	
	/* App_Precedence identifies the priority of each application accessing the datastores. */
	int [] App_Precedence = new int [Number_of_Applications];
		
	/*---------- Rule ID Inventory ----------*/
	String [] RuleIDInventory = new String [C];
	
	/*---------- Source IP Inventory ----------*/
	String [] SourceIPInventory = new String [C];
	
	/*---------- Destination IP Inventory ----------*/
	String [] DestinationIPInventory = new String [C];
	
	/*---------- Source Port Inventory ----------*/
	String [] SourcePortInventory = new String [C];
	
	/*---------- Destination Port Inventory ----------*/
	String [] DestinationPortInventory = new String [C];

	/*---------- Priority Inventory ----------*/
	int [] PriorityInventory = new int [C];
	
	/*---------- Action Inventory ----------*/
	String [] ActionInventory = new String [C];
			
	int Universal_Counter = 0; 
	
	public AntivirusImpl (DataBroker db) {
		this.db = db;
		initializeDataTree(db);
		App_Inventory = initialize_App_Inventory();
		App_Precedence = Set_App_Precedence(1);
		
		SourcePortInventory = initialize_String_Array (SourcePortInventory);
		DestinationPortInventory = initialize_String_Array (DestinationPortInventory);
		SourceIPInventory = initialize_String_Array (SourceIPInventory);
		DestinationIPInventory = initialize_String_Array (DestinationIPInventory);
		PriorityInventory = initialize_Integer_Array (PriorityInventory);
		ActionInventory = initialize_String_Array (ActionInventory);
		
		Password_Dictionary = initialize_Password_Dictionary ();
		Threshold_Inventory = Set_Threshold_Inventory(1);
	}	

	public String[] initialize_Password_Dictionary () {
		
		for (int i = 0; i < Password_Dictionary.length; i++) {
			Password_Dictionary[i] = Integer.toString(i);
		}
		return Password_Dictionary;
	}
	
	public int[] Fair_Resource_Allocation () {
		
		int threshold;
		
		for (int i = 0; i < Threshold_Inventory.length; i++)
		{
			/*---------- Fairness (conceived in terms of the ideal of equal) Resource Allocation ----------*/
			threshold = C/Number_of_Applications;
			Threshold_Inventory [i] = threshold;
		}
		return Threshold_Inventory;
	}

	public int[] Role_Based_Resource_Allocation () {
		/*---------- Note that Space and Threshold should always be whole numbers.*/
		int SpaceForTierOneApplications;
		int SpaceForTierTwoApplications;
		int SpaceForTierThreeApplications;
		int ThresholdForTierOneApplications;
		int ThresholdForTierTwoApplications;
		int ThresholdForTierThreeApplications;
		
		SpaceForTierOneApplications = C*50;
		SpaceForTierTwoApplications = C*30;
		SpaceForTierThreeApplications = C*20;
		
		SpaceForTierOneApplications = SpaceForTierOneApplications/100;
		SpaceForTierTwoApplications = SpaceForTierTwoApplications/100;
		SpaceForTierThreeApplications = SpaceForTierThreeApplications/100;
		
		ThresholdForTierOneApplications = SpaceForTierOneApplications/TierOneApplications;
		ThresholdForTierTwoApplications = SpaceForTierTwoApplications/TierTwoApplications;
		ThresholdForTierThreeApplications = SpaceForTierThreeApplications/TierThreeApplications;
		
		for (int i = 0; i < Threshold_Inventory.length; i++) {
			if (App_Precedence[i] == 0) {
				Threshold_Inventory[i] = ThresholdForTierOneApplications;
			}
			else if (App_Precedence[i] == 1) {
				Threshold_Inventory[i] = ThresholdForTierTwoApplications;
			}
			else if (App_Precedence[i] == 2) {
				Threshold_Inventory[i] = ThresholdForTierThreeApplications;
			}
		}
		return Threshold_Inventory;
	}
	
	public int[] initialize_App_Inventory () {
		for (int i = 0; i < App_Inventory.length; i++)
		{
			App_Inventory [i] = 0;
		}
		return App_Inventory;		
	}
	
	public int[] Set_Threshold_Inventory (int Mode) {
		/* Mode can be:
		 * 0 -- Fair Resource Allocation
		 * 1 -- Role Based Resource Allocation
		 * 2 -- Resource Allocation as an Optimization Problem */
		if (Mode == 0) {
			Threshold_Inventory = Fair_Resource_Allocation ();
		}
		else if (Mode == 1) {
			Threshold_Inventory = Role_Based_Resource_Allocation ();
		}
		else {
			// do nothing
		}
		return Threshold_Inventory;
	}
	
	public int[] Set_App_Precedence (int Mode) {
		/* Mode can be:
		 * 0 -- Fair Resource Allocation
		 * 1 -- Role Based Resource Allocation
		 * 2 -- Resource Allocation as an Optimization Problem */
		
		if (Mode == 0) {
			for (int i = 0; i < App_Precedence.length; i++)
			{
				App_Precedence [i] = 0;
			}			
		}
		else if (Mode == 1) {
			for (int i = 0; i < App_Precedence.length; i++) {
				if (i <= 200) // First 200 applications are randomly given a precedence of 0.
				{ 
					App_Precedence [i] = 0;
				}
				else if (i <= 300) {
					App_Precedence [i] = 1;
				}
				else if (i < 400) {
					App_Precedence [i] = 2;
				}
				else {
					// do nothing
				}
			}
		}
		else if (Mode == 2) {
			// Coding remaining
		}
		return App_Precedence;
	}
		
	public int[] initialize_Integer_Array (int [] Integer_Array) {
		for (int i =0; i < Integer_Array.length; i++) {
			Integer_Array [i] = 0;
		}
		return Integer_Array;
	}
		
	public String[] initialize_String_Array (String [] String_Array) {
		for (int i=0; i< String_Array.length; i++) {
			String_Array [i] = "";
		}
		return String_Array;
	}
		
	public boolean check_format_AppID (String App_ID) {
		boolean correct_format = false;
		
		try {

			if ((Integer.parseInt(App_ID) >= 0) && (Integer.parseInt(App_ID) <= 399))
			{
				LOG.info("Format is correct");
				correct_format = true;
			}
			else 
			{
				correct_format = false;
				LOG.info("Format is incorrect");
			}
		}
		catch(NumberFormatException e) {
			correct_format = false;
			LOG.info("Format is an exception.");
		}
		return correct_format;
	}

	public boolean check_format_Operation (int operation)
	{
		boolean correct_format = false;
		
		if ((operation == 0) || (operation == 1))
		{
			correct_format = true;
		}
		else 
		{
			correct_format = false;
		}
		return correct_format;
	}
	
	public boolean check_format_RuleID (String RuleID, int AppID) {
		
		boolean correct_format = false;
	    boolean format_correct = true;
	    StringBuilder sb = new StringBuilder();
        String str;
		int AppID_part = 0;
		int RuleNumber_part = 0;
		int j = 0;
		
		for (int i = 0; i < RuleID.length(); i++) 
		{
			if (RuleID.charAt(i) == ':')
			{
				j = j + 1;
                str = sb.toString();
                AppID_part = Integer.parseInt(str);
	                
                if ((AppID_part >= 0) && (AppID_part <= 399) && (AppID_part == AppID))
                {
                    str = "";
                    sb = new StringBuilder();
                    format_correct = true && format_correct;
                }
                else
                {
                	format_correct = false;
                }
			}
			else if (RuleID.charAt(i) == '.')
			{
				j = j + 1;
				str = sb.toString();
				RuleNumber_part = Integer.parseInt(str);
				
				if ((RuleNumber_part > 0) && (RuleNumber_part <= Threshold_Inventory[AppID_part])) 
				{
					format_correct = true && format_correct;
				}
				else
				{
					format_correct = false;
				}
			}
	        else 
	        {
	            sb.append(RuleID.charAt(i));
	        }			
		}
		
		if ( (j==2) && (format_correct == true) ) {
			correct_format = true;
		}
		else {
			correct_format = false;
		}

		return correct_format;
	}
		
	public boolean check_format_ports (String port) {
		
		boolean correct_format = false;
		String ANY = "ANY";
		String NONE = "NONE";
		String any = "any";
		String none = "none";
		String Any = "Any";
		String None = "None";
		
		if ((port.equals(ANY)) || (port.equals(NONE)) || (port.equals(any)) || (port.equals(none)) || (port.equals(Any)) || (port.equals(None)))
		{
			correct_format = true;
		}
		
		else if (((Integer.parseInt(port) > 1024) && (Integer.parseInt(port) < 65536)))
		{
			correct_format = true;
		}
		else {
			correct_format = false;
		}
		return correct_format;
	}
	
	public boolean check_format_action (String action) {
		
		boolean correct_format = false;
		/*---------- Different formats allowed for Action ----------*/
		String ALLOW = "ALLOW";
		String DENY = "DENY";
		String allow = "allow";
		String deny = "deny";
		String Allow = "Allow";
		String Deny = "Deny";
		
		if ((action.equals(ALLOW)) || (action.equals(DENY)) || (action.equals(allow)) || (action.equals(deny)) || (action.equals(Allow)) || (action.equals(Deny)))
		{
			correct_format = true;
		}
		else {
			correct_format = false;
		}
		return correct_format;
	}
			
	public boolean check_format_IP_address (String IP_address) {
		int number_of_dots = 0;
		int k = 0;
	    StringBuilder sb = new StringBuilder();
	    boolean format_correct = true;
	    boolean correct_format = false;
	    int backslash = 0;
        String str;
		
	    for (int i = 0; i < IP_address.length(); i++)
	    {
            if (IP_address.charAt(i) == '.') 
            {
                str = sb.toString();
                k = Integer.parseInt(str);
	                
                if (backslash == 0) {
                    if ((k >= 0) && (k <= 255))
                    {
                        str = "";
                        sb = new StringBuilder();
                        format_correct = true && format_correct;
                    }
                    else 
                    {
                        format_correct = false;
                    }                	                            	
                }
                else {
                	if ((k >= 8) || (k <= 32)) {
                		format_correct = true && format_correct;
                	}
                	else {
                		format_correct = false;
                	}
                }

                number_of_dots = number_of_dots + 1;
            }
            else if (IP_address.charAt(i) == '/') {
            	backslash = 1;
            }
	        else 
	        {
	            sb.append(IP_address.charAt(i));
	        }
	  }
	        
	  if ((number_of_dots == 4) && (backslash == 1) && (format_correct)) 
	  {
		  correct_format = true;
		  LOG.info ("The IP Format is correct.");
	  }
	  else
	  {
		  correct_format = false;
		  LOG.info ("The IP Format is not correct.");
	  }
	  return correct_format;
	}

	public boolean check_Password (String Password, int AppID) {
		boolean PasswordCorrect = false;
		
			if (Password.equals(Password_Dictionary[AppID])) {
				PasswordCorrect = true;
			}
			else {
				PasswordCorrect = false;
			}
		
		return PasswordCorrect;
	}
	
	public int FindHighPriorityApp (int AppID1, int AppID2) {
		
		if (App_Precedence[AppID1] == App_Precedence[AppID2]) {
			if (AppID1 > AppID2) {
				return AppID1; 				
			}
			else {
				return AppID2;
			}
		}
		else if (App_Precedence[AppID1] < App_Precedence[AppID2]) {
			return AppID2;
		}
		else if (App_Precedence[AppID1] > App_Precedence[AppID2]){
			return AppID1;
		}
		else {
			return -1;
		}
	}

	public String[] StoreRules (ApplicationHelloInput input) {
		String RuleID = input.getRuleID();
		String SourceIP = input.getSourceIP();
		String DestinationIP = input.getDestinationIP();
		String SourcePort = input.getSourcePort();
		String DestinationPort = input.getDestinationPort();
		int Priority = input.getPriority();
		String Action = input.getAction();
		boolean duplicate_rule = false;
		String [] duplicate_rule_parameters = {"false","-2"};
		
		
		if (Universal_Counter == 0) {
			RuleIDInventory [Universal_Counter] = RuleID;
			SourceIPInventory [Universal_Counter] = SourceIP;
			DestinationIPInventory [Universal_Counter] = DestinationIP;
			PriorityInventory[Universal_Counter] = Priority;
			ActionInventory[Universal_Counter] = Action;
			
			if ( (SourcePort.equals("ANY")) || (SourcePort.equals("NONE")) || (SourcePort.equals("any")) || (SourcePort.equals("none"))
				 || (SourcePort.equals("Any")) || (SourcePort.equals("None")))
			{
				SourcePortInventory [Universal_Counter] = "0";
				DestinationPortInventory [Universal_Counter] = "0";
			}
			else {
				SourcePortInventory [Universal_Counter] = SourcePort;				
				DestinationPortInventory [Universal_Counter] = DestinationPort;
			}
			
			Universal_Counter = Universal_Counter + 1;			
		}
		else {
			duplicate_rule_parameters = checkDuplicateRules (input);
			
			if (duplicate_rule_parameters[0].equals("true")) {
				LOG.info("Rule Found " + duplicate_rule_parameters[0]);
				// do not store
			}
			else {
				RuleIDInventory [Universal_Counter] = RuleID;
				SourceIPInventory [Universal_Counter] = SourceIP;
				DestinationIPInventory [Universal_Counter] = DestinationIP;
				SourcePortInventory [Universal_Counter] = SourcePort;
				DestinationPortInventory [Universal_Counter] = DestinationPort;
				PriorityInventory[Universal_Counter] = Priority;
				ActionInventory[Universal_Counter] = Action;
				Universal_Counter = Universal_Counter + 1;							
			}
		}
		return duplicate_rule_parameters;
	}
	
	public String[] checkDuplicateRules (ApplicationHelloInput input) {
		int current_AppID = Integer.parseInt(input.getAppID());
		String current_RuleID = input.getRuleID();
		String SourceIP = input.getSourceIP();
		String DestinationIP = input.getDestinationIP();
		String SourcePort = input.getSourcePort();
		String DestinationPort = input.getDestinationPort();
		int Priority = input.getPriority();
		String Action = input.getAction();
		
		int HighPriorityApp = -2;
		int match_fields = 0;
		boolean duplicate_rule = false;
		String RuleID = null;
		String str;
		int AppID_part = -2;
	    StringBuilder sb = new StringBuilder();
		String [] duplicate_rule_parameters = new String [2];
	    int i = 0;
		
		for (i = 0; i <= Universal_Counter; i++) {
			
			match_fields = 0;
			
			if (SourceIPInventory[i].equals(SourceIP)) {
				match_fields = match_fields + 1;
			}
			
			if (DestinationIPInventory[i].equals(DestinationIP)) {
				match_fields = match_fields + 1;
			}
			
			if ( (SourcePortInventory[i].equals(SourcePort) || (SourcePort.equals("0"))))
			{
				match_fields = match_fields + 1;
			}
			
			if ( (DestinationPortInventory[i].equals(DestinationPort)) || (DestinationPort.equals("0")) )
			{
				match_fields = match_fields + 1;
			}
			
			if ( (PriorityInventory[i] == Priority)) 
			{
				match_fields = match_fields + 1;
			}
			
			if ( (Action.equals("ALLOW")) || (Action.equals("allow")) || (Action.equals("Allow")) ) {
				if ( (ActionInventory[i].equals("Allow")) || (ActionInventory[i].equals("ALLOW")) || (ActionInventory[i].equals("allow")) ) {
					match_fields = match_fields + 1;
				}
				else {
					//do nothing
				}
			}
			
			else if ( (Action.equals("DENY")) || (Action.equals("deny")) || (Action.equals("Deny")) ) {
				if ( (ActionInventory[i].equals("Deny")) || (ActionInventory[i].equals("DENY")) || (ActionInventory[i].equals("deny"))) {
			 		match_fields = match_fields + 1;
				}
				else {
					//do nothing
				}
			}
						
			if (match_fields == 6) {
				duplicate_rule = true;
				RuleID = RuleIDInventory[i]; //Rule ID has format AppID:Rule Number
				
				for (int j = 0; j < RuleID.length(); j++) {
					if (RuleID.charAt(j) == ':')
					{
		                str = sb.toString();
		                AppID_part = Integer.parseInt(str);
						break;
					}
					else {
				            sb.append(RuleID.charAt(j));
				        }			
				}

				HighPriorityApp = FindHighPriorityApp (current_AppID, AppID_part);

				if (HighPriorityApp == AppID_part) 
				{
					// do nothing
				}
				else // delete the old rule and store it again with the current AppID. 
				{
//					ModifyRuleRegistry (i,current_RuleID);
				}	
				
                break;
			}
			else {
				duplicate_rule = false;
			}
		}
		
		duplicate_rule_parameters [0] = Boolean.toString(duplicate_rule);
		duplicate_rule_parameters [1] = String.valueOf(HighPriorityApp);					
		
		return duplicate_rule_parameters;		
	}

	public void ModifyRuleRegistry (int i, String RuleID) {
		ReadWriteTransaction transaction = db.newReadWriteTransaction();
	    InstanceIdentifier<ConfigurationRulesRegistryEntry> iid = toInstanceIdentifier(RuleID);
		        
        transaction.delete(LogicalDatastoreType.CONFIGURATION, iid);	
				CheckedFuture<Void, org.opendaylight.controller.md.sal.common.api.data.TransactionCommitFailedException> future = transaction.submit();
				Futures.addCallback(future, new LoggingFuturesCallBack<Void>("Failed to delete a rule", LOG));
	}
	
	public String Decision_Engine (ApplicationHelloInput input) {
		
		int current_AppID = Integer.parseInt(input.getAppID());
		int operation = input.getOperation();  // The operation to be performed.
		
		boolean duplicate_rule = false;
		String [] duplicate_rule_parameters;
		String Greeting_Message = null;
				
		if (operation == 0) 
		{
			result = readFromruleRegistry (input); // Check if rule is already present
			
			if (result == "Rule Found")
			{
				Greeting_Message = "Rule ID: " + input.getRuleID() + " for App ID: " +input.getAppID() + " already exists.";
			}
			else 
			{
				duplicate_rule_parameters = StoreRules (input);
				
				if (duplicate_rule_parameters[0].equals("true")) {
					Greeting_Message = "The rule exists for App ID: " + duplicate_rule_parameters[1];
				}
				
				else {
					writeToRuleRegistry(input);
					App_Inventory[current_AppID] = App_Inventory[current_AppID] + 1;
					Greeting_Message = "Rule ID: " + input.getRuleID() + " for App ID: " +input.getAppID() + " stored.";										
				}
			}
		}
		else // (operation == 1)
		{
			result = readFromruleRegistry (input);
			if (result == "Rule Found")
			{
				deletefromRuleRegistry (input);
    			App_Inventory[current_AppID] = App_Inventory[current_AppID] - 1;
    			Greeting_Message = "Rule ID: " + input.getRuleID() + "for App ID: " +input.getAppID() + " deleted.";
    		}
    		else
    		{
    			Greeting_Message = "Rule ID: " + input.getRuleID() + " for App ID: " +input.getAppID() + " does not exist.";
    		}
		}
		return Greeting_Message;
	}

	private void initializeDataTree(DataBroker db) {
		final Logger LOG = LoggerFactory.getLogger(AntivirusImpl.class);		
        LOG.info("Preparing to initialize the greeting registry");
        WriteTransaction transaction = db.newWriteOnlyTransaction();
        InstanceIdentifier<ConfigurationRulesRegistry> iid = InstanceIdentifier.create(ConfigurationRulesRegistry.class);
        ConfigurationRulesRegistry ruleregistry = new ConfigurationRulesRegistryBuilder()
                .build();
        transaction.put(LogicalDatastoreType.OPERATIONAL, iid, ruleregistry);
        transaction.put(LogicalDatastoreType.CONFIGURATION, iid, ruleregistry);
        CheckedFuture<Void, TransactionCommitFailedException> future = transaction.submit();
        Futures.addCallback(future, new LoggingFuturesCallBack<>("Failed to create rule registry", LOG));
    }
		
	private InstanceIdentifier<ConfigurationRulesRegistryEntry> toInstanceIdentifier(String RuleID) {
	        InstanceIdentifier<ConfigurationRulesRegistryEntry> iid = InstanceIdentifier.create(ConfigurationRulesRegistry.class)
	            .child(ConfigurationRulesRegistryEntry.class, new ConfigurationRulesRegistryEntryKey(RuleID));
	        return iid;
	    }
	
	private void writeToRuleRegistry(ApplicationHelloInput input_rule) {
	    WriteTransaction transaction = db.newWriteOnlyTransaction();
	    InstanceIdentifier<ConfigurationRulesRegistryEntry> iid = toInstanceIdentifier(input_rule.getRuleID());
	    ConfigurationRulesRegistryEntry ruleregistry = new ConfigurationRulesRegistryEntryBuilder()
	    		.setAppID(input_rule.getAppID())
	    		.setOperation(input_rule.getOperation())
	            .setRuleID(input_rule.getRuleID())
	            .setSourceIP(input_rule.getSourceIP())
	            .setDestinationIP(input_rule.getDestinationIP())
	            .setSourcePort(input_rule.getSourcePort())
	            .setDestinationPort(input_rule.getDestinationPort())
	            .setPriority(input_rule.getPriority())
	            .setAction(input_rule.getAction())
	            .build();
	    transaction.put(LogicalDatastoreType.CONFIGURATION, iid, ruleregistry);
	    CheckedFuture<Void, TransactionCommitFailedException> future = transaction.submit();
	    Futures.addCallback(future, new LoggingFuturesCallBack<Void>("Failed to write a rule", LOG));
		}

	public void deletefromRuleRegistry (ApplicationHelloInput input_rule) {
		ReadWriteTransaction transaction = db.newReadWriteTransaction();
		InstanceIdentifier<ConfigurationRulesRegistryEntry> iid = toInstanceIdentifier(input_rule.getRuleID());
		transaction.delete(LogicalDatastoreType.CONFIGURATION, iid);	
		CheckedFuture<Void, org.opendaylight.controller.md.sal.common.api.data.TransactionCommitFailedException> future = transaction.submit();
		Futures.addCallback(future, new LoggingFuturesCallBack<Void>("Failed to delete a rule", LOG));
		}
	
	private String readFromruleRegistry (ApplicationHelloInput input) {
	    String result = null;
	    ReadOnlyTransaction transaction = db.newReadOnlyTransaction();
	    InstanceIdentifier<ConfigurationRulesRegistryEntry> iid = toInstanceIdentifier(input.getRuleID());
	    CheckedFuture<Optional<ConfigurationRulesRegistryEntry>, ReadFailedException> future =
	            transaction.read(LogicalDatastoreType.CONFIGURATION, iid);
	    Optional<ConfigurationRulesRegistryEntry> optional = Optional.absent();
	    try {
	        optional = future.checkedGet();
	    } catch (ReadFailedException e) {
	        LOG.warn("Reading greeting failed:",e);
	    }
	    if(optional.isPresent()) {
	    	result = "Rule Found";
	    }
	    return result;
		}
	
	public String checkInputFormat (ApplicationHelloInput input) {
		String Greeting_Message = null;
		boolean check_Operation_format = check_format_Operation (input.getOperation());
		boolean check_Rule_ID_format = check_format_RuleID (input.getRuleID(), Integer.parseInt(input.getAppID()));
		boolean check_format_SourceIP = check_format_IP_address (input.getSourceIP());
		boolean check_format_DestinationIP = check_format_IP_address (input.getDestinationIP());
		boolean check_source_port_format = check_format_ports (input.getSourcePort());
		boolean check_destination_port_format = check_format_ports(input.getDestinationPort());
		boolean check_format_action = check_format_action (input.getAction());

		boolean check_format = check_Operation_format && check_Rule_ID_format && check_format_SourceIP  
				               && check_format_DestinationIP && check_source_port_format && check_destination_port_format 
				               && check_format_action;
		
		if (check_format)
		{
			Greeting_Message = Decision_Engine (input);
			LOG.info("Format is correct.");
		}
		else
		{
			if (check_Operation_format == false) 
			{
				Greeting_Message = "Operation can be 0 for addition and 1 for deletion. Try Again!.";
				LOG.info("Format for Operation is not correct.");
			}
			else if (check_Rule_ID_format == false) 
			{
				Greeting_Message = "Check Rule ID format, X:Y. (X is the AppID and Y is the rule number). Make sure rule number is within limits (Limit = " +
						Threshold_Inventory[current_AppID] +").";
				LOG.info("Format for Rule ID is not correct.");
			}
			else if (check_format_SourceIP == false)
			{
				Greeting_Message = "The format for Source IP is X.X.X.X/X.; Try Again!.";
				LOG.info ("Format for Source IP Address is not correct.");
			}
			else if (check_format_DestinationIP == false)
			{
				Greeting_Message = "The format for Destination IP is X.X.X.X/X.; Try Again.";
				LOG.info ("Format for Source IP Address is not correct.");
			}
			else if (check_source_port_format == false)
			{
				Greeting_Message = "The range for Source Port lies between 1025 and 65535. Try Again.";
				LOG.info ("Format for Source Port is not correct");
			}
			else if (check_destination_port_format == false)
			{
				Greeting_Message = "The range for Destination Port lies between 1025 and 65535. Try Again.";
				LOG.info ("Format for Destination Port is not correct");
			}
			else // check_format_action = false
			{
				Greeting_Message = "The specified action can only be ALLOW or DENY. Try Again.";
				LOG.info ("Format for Action is not correct");				
			}
		}
		return Greeting_Message;
	}	

	@Override
	public Future<RpcResult<ApplicationHelloOutput>> applicationHello (ApplicationHelloInput input) {
		String Greeting_Message = null;
		boolean check_App_ID_format;
		int current_AppID;
		int Counter; 
		boolean PasswordCorrect;
		
		check_App_ID_format = check_format_AppID(input.getAppID());
		Counter = 0;
		
		if (check_App_ID_format == true) {
			current_AppID = Integer.parseInt(input.getAppID());
			
			PasswordCorrect = check_Password (input.getPassword(), current_AppID);
			
			if (PasswordCorrect) {
				Greeting_Message = checkInputFormat (input);			
				Counter = App_Inventory[current_AppID];						
			}
			else {
				Greeting_Message = "Password is not correct. Try Again!";
			}
		}
		else
		{
			Greeting_Message = "App ID is a number between 1 and 400. Try Again!";
		}
		
		ApplicationHelloOutput output = new ApplicationHelloOutputBuilder()
					  .setGreeting(Greeting_Message)
					  .setCounter(String.valueOf(Counter))
					  .build();
		return RpcResultBuilder.success(output).buildFuture();
		}

}