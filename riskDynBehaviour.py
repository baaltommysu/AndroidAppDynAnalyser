import csv


NULL                    = 0
AVERAGE                 = 1
HIGH                    = 2

    
GENERAL_RISK            = 0
MONEY_RISK              = 1 
SMS_RISK                = 2
PHONE_RISK              = 3
INTERNET_RISK           = 4
PRIVACY_RISK            = 5 
DYNAMIC_RISK            = 6
BINARY_RISK             = 7
EXPLOIT_RISK            = 8
#ROOT_PRIV_RISK          = 9
ENCRYPTED_CODE_RISK     = 10
MALWARE_RISK            = 11

risk_values_calculate = {
                	GENERAL_RISK            : 5, 
	                MONEY_RISK              : 5,
        	        SMS_RISK                : 5,
        	        PHONE_RISK              : 5,
        	        INTERNET_RISK           : 5,
        	        PRIVACY_RISK            : 5,
        	        DYNAMIC_RISK            : 5,
        	        BINARY_RISK             : 5,
        	        EXPLOIT_RISK            : 5,
        	        ENCRYPTED_CODE_RISK     : 5
}   



ACTIVITIES_RISK = {

    	"FILE_READ"					: [ PRIVACY_RISK, EXPLOIT_RISK, PHONE_RISK ],
	"FILE_WRITE"					: [ EXPLOIT_RISK, PHONE_RISK ],
        "FILES_LEAKAGE"                                 : [ PRIVACY_RISK, PHONE_RISK],

	"CRYPTO_API"					: [ ENCRYPTED_CODE_RISK ],
	
	"OPEN_CONN"					: [ INTERNET_RISK ],
	"OUTGOING_TRAF"					: [ INTERNET_RISK, MONEY_RISK ],
	"INCOMING_TRAF"					: [ INTERNET_RISK, MONEY_RISK, PHONE_RISK],
        "INTERNET_LEAKAGE"                              : [ INTERNET_RISK, PRIVACY_RISK, MONEY_RISK],

	"DEX_CLASS_LOADER"				: [ DYNAMIC_RISK, BINARY_RISK ],

	"BROADCAST_RECEIVER"				: [ DYNAMIC_RISK ],
	"START_SERVICE"					: [ DYNAMIC_RISK, PHONE_RISK ],
	"ENFORCED_PERMISSION"				: [ DYNAMIC_RISK ],
	"BYPASSED_PERMISSION"				: [ DYNAMIC_RISK, PHONE_RISK],

	"INFO_LEAKAGE_SMS"				: [ SMS_RISK, PRIVACY_RISK ],
	"INFO_LEAKAGE_OTHERS"			        : [ PRIVACY_RISK, PHONE_RISK ],
#information leaked from other places / from sms

	"SENT_SMS_LEAKAGE"				: [ SMS_RISK, MONEY_RISK, PRIVACY_RISK ],
	"SENT_SMS_NORMAL"				: [ SMS_RISK, MONEY_RISK],
	
	"PHONE_CALLS"					: [ MONEY_RISK ],

}



HIGH_RISK                   = "high"
LOW_RISK                    = "low"
AVERAGE_RISK                = "average"
UNACCEPTABLE_RISK           = "unacceptable"

NULL_MALWARE_RISK           = "null"
AVERAGE_MALWARE_RISK        = "average"
HIGH_MALWARE_RISK           = "high"
UNACCEPTABLE_MALWARE_RISK   = "unacceptable"




    
        
           
def add_system_rule(system, rule_name, rule) :
    system.rules[ rule_name ] = rule
    return
    
def create_system_risk() :
    try :
        import fuzzy
    except ImportError :
        error("please install pyfuzzy to use this module !")

    import fuzzy.System
    import fuzzy.InputVariable
    import fuzzy.fuzzify.Plain
    import fuzzy.OutputVariable
    import fuzzy.defuzzify.COGS
    import fuzzy.set.Polygon
    import fuzzy.set.Singleton
    import fuzzy.set.Triangle
    import fuzzy.Adjective
    import fuzzy.operator.Input
    import fuzzy.operator.Compound
    import fuzzy.norm.Min
    import fuzzy.norm.Max
    import fuzzy.Rule
        
    system = fuzzy.System.System()

    input_Money_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_SMS_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Privacy_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Binary_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Internet_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Dynamic_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Phone_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain()) 
    input_Encrypted_Code_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())   
    input_Exploit_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())

        
    # Input variables
        
    # SMS Risk
    system.variables["input_SMS_Risk"] = input_SMS_Risk
    input_SMS_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (3.0, 0.0)]) )
    input_SMS_Risk.adjectives[AVERAGE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(2.0, 0.0), (5.0, 1.0), (10.0, 0.0)]) )
    input_SMS_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 0.0),(5.0, 1.0), (10.0, 1.0)]) )

    # Money Risk
    system.variables["input_Money_Risk"] = input_Money_Risk
    input_Money_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (10.0, 0.0)]) )
    input_Money_Risk.adjectives[AVERAGE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(5.0,0.0), (10.0, 1.0), (15.0, 0.0)]) )
    input_Money_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(10.0, 0.0), (15.0, 1.0), (30.0, 1.0)]) )

    # Privacy Risk
    system.variables["input_Privacy_Risk"] = input_Privacy_Risk
    input_Privacy_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (10.0, 0.0)]) )
    input_Privacy_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(5.0, 0.0), (15.0, 1.0), (30.0, 1.0)]))

    # Binary Risk
    system.variables["input_Binary_Risk"] = input_Binary_Risk
    input_Binary_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (4.0, 0.0)]) )
    input_Binary_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(4.0, 0.0), (5.0, 1.0), (10.0, 1.0)]) )

    # Internet Risk
    system.variables["input_Internet_Risk"] = input_Internet_Risk
    input_Internet_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (5.0,1.0), (10.0, 0.0)]) )
    input_Internet_Risk.adjectives[AVERAGE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(5.0,1.0),(10.0, 1.0), (15.0, 0.0)]) )
    input_Internet_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(5.0, 0.0), (10.0, 1.0), (30.0, 1.0)]))

    # Phone Risk
    system.variables["input_Phone_Risk"] = input_Phone_Risk
    input_Phone_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (5.0, 1.0), (10.0, 0.0)]) )
    input_Phone_Risk.adjectives[AVERAGE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(5.0, 0.0), (10.0, 1.0), (15.0, 0.0)]) )
    input_Phone_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(10.0, 0.0), (15.0, 1.0), (30.0, 1.0)]))
     
    # Dynamic Risk
    system.variables["input_Dynamic_Risk"] = input_Dynamic_Risk
    input_Dynamic_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (4.0, 0.0)]) )
    input_Dynamic_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(4.0, 0.0),(5.0, 1.0), (10.0, 1.0)]) )
  
    # Exploit Risk
    system.variables["input_Exploit_Risk"] = input_Exploit_Risk
    input_Exploit_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (4.0, 0.0)]) )
    input_Exploit_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(4.0, 0.0), (5.0, 1.0), (15.0, 1.0),]) )
        
    # Encrypted Risk
    system.variables["input_Encrypted_Code_Risk"] = input_Encrypted_Code_Risk
    input_Encrypted_Code_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (4.0, 0.0)]) )
    input_Encrypted_Code_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(4.0, 0.0), (5.0, 1.0)]) )


 
    # Output variables
    output_malware_risk = fuzzy.OutputVariable.OutputVariable(
                                defuzzify=fuzzy.defuzzify.COGS.COGS(),
                                description="malware risk",
                                min=0.0,max=100.0,
                            )

    output_malware_risk.adjectives[NULL_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(0.0))
    output_malware_risk.adjectives[AVERAGE_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(50.0))
    output_malware_risk.adjectives[HIGH_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(70.0))
    output_malware_risk.adjectives[UNACCEPTABLE_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(100.0))

    system.variables["output_malware_risk"] = output_malware_risk
    # Rules

    #rule 1 if BINARY_RISK is HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r1", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Binary_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 2 if EXPLOIT_RISK is HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r2", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Exploit_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 3 if ENCRYPTED_CODE_RISK is HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r3", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Encrypted_Code_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 4 if SMS_RISK is HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r4", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_SMS_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 4a if SMS_RISK is AVERAGE, then output is HIGH;
    add_system_rule(system, "r4a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_SMS_Risk"].adjectives[AVERAGE_RISK] )
                        )
        )

    #rule 5 if INTERNET_RISK is HIGH, then output is HIGH;
    add_system_rule(system, "r5", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 6 if Dynamic_RISK is HIGH, then output is HIGH;
    add_system_rule(system, "r6", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Dynamic_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 7 if Privacy_RISK is HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r7", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 7a if Privacy_RISK is LOW, then output is NULL;
    add_system_rule(system, "r7a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] )
                        )
        )

    #rule 8 if Phone_RISK is HIGH, then output is HIGH;
    add_system_rule(system, "r8", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 8a if Phone_RISK is AVERAGE, then output is AVERAGE;
    add_system_rule(system, "r8a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] )
                        )
        )

    #rule 9 if Money_RISK is HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r9", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Money_Risk"].adjectives[HIGH_RISK] )
                        )
        )

    #rule 9a if Money_RISK is AVERAGE, then output is HIGH;
    add_system_rule(system, "r9a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] )
                        )
        )

    #rule 9b if Money_RISK is LOW, then output is NULL;
    add_system_rule(system, "r9b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],                     
                                            operator=fuzzy.operator.Input.Input(system.variables["input_Money_Risk"].adjectives[LOW_RISK] )
                        )
        )


#For sent_sms_leakage

    #rule 10 if SMS_Risk is HIGH AND Privacy_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r10", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[HIGH_RISK] ))
                        )
        )    

    #rule 10a if SMS_Risk is HIGH AND Privacy_Risk LOW, then output is HIGH;
    add_system_rule(system, "r10a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 10b if SMS_Risk is AVERAGE AND Privacy_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r10b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 10c if SMS_Risk is AVERAGE AND Privacy_Risk LOW, then output is AVERAGE;
    add_system_rule(system, "r10c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 10d if SMS_Risk is LOW AND Privacy_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r10d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 10e if SMS_Risk is LOW AND Privacy_Risk LOW, then output is NULL;
    add_system_rule(system, "r10e", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[LOW_RISK] ))
                        )
        )


    #rule 11 if SMS_Risk is HIGH AND Money_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r11", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 11a if SMS_Risk is HIGH AND Money_Risk AVERAGE, then output is HIGH;
    add_system_rule(system, "r11a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 11b if SMS_Risk is AVERAGE AND Money_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r11b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 11c if SMS_Risk is AVERAGE AND Money_Risk AVERAGE, then output is AVERAGE;
    add_system_rule(system, "r11c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 11d if SMS_Risk is LOW AND Money_Risk LOW, then output is NULL;
    add_system_rule(system, "r11d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[LOW_RISK] ))
                        )
        )


    #rule 12 if Privacy_Risk is HIGH AND Money_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r12", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )


    #rule 12a if Privacy_Risk is HIGH AND Money_Risk AVERAGE, then output is HIGH;
    add_system_rule(system, "r12a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )


    #rule 12b if Privacy_Risk is LOW AND Money_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r12b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 12c if Privacy_Risk is LOW AND Money_Risk AVERAGE, then output is AVERAGE;
    add_system_rule(system, "r12c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 12d if Privacy_Risk is LOW AND Money_Risk LOW, then output is NULL;
    add_system_rule(system, "r12d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ))
                        )
        )


    #rule 13 if SMS_Risk is HIGH, Privacy_Risk is HIGH AND Money_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r13", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 13a if SMS_Risk is LOW, Privacy_Risk is LOW AND Money_Risk LOW, then output is NULL;
    add_system_rule(system, "r13a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_SMS_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ))
                        )
        )

#For INTERNET_LEAKAGE;

    #rule 14 if Internet_Risk is HIGH AND Privacy_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r14", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ))
                        )
        )    

    #rule 14a if Internet_Risk is HIGH AND Privacy_Risk LOW, then output is HIGH;
    add_system_rule(system, "r14a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 14b if Internet_Risk is LOW AND Privacy_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r14b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 14c if Internet_Risk is LOW AND Privacy_Risk LOW, then output is NULL;
    add_system_rule(system, "r14c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 15 if Internet_Risk is HIGH AND Money_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r15", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 15a if Internet_Risk is HIGH AND Money_Risk AVERAGE, then output is HIGH;
    add_system_rule(system, "r15a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 15b if Internet_Risk is HIGH AND Money_Risk LOW, then output is AVERAGE;
    add_system_rule(system, "r15b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 15c if Internet_Risk is LOW AND Money_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r15c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 15d if Internet_Risk is LOW AND Money_Risk AVERAGE, then output is AVERAGE;
    add_system_rule(system, "r15d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[AVERAGE_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 15e if Internet_Risk is LOW AND Money_Risk LOW, then output is NULL;
    add_system_rule(system, "r15e", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 16 if Internet_Risk is HIGH, Privacy_Risk is HIGH AND Money_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r16", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 16a if Internet_Risk is LOW, Privacy_Risk is LOW AND Money_Risk LOW, then output is NULL;
    add_system_rule(system, "r16a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ))
                        )
        )

#For file leakage;

    #rule 17 if Phone_Risk is HIGH AND Privacy_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r17", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] ))
                        )
        )    

    #rule 17a if Phone_Risk is HIGH AND Privacy_Risk LOW, then output is HIGH;
    add_system_rule(system, "r17a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 17b if Phone_Risk is AVERAGE AND Privacy_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r17b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 17c if Phone_Risk is AVERAGE AND Privacy_Risk LOW, then output is AVERAGE;
    add_system_rule(system, "r17c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 17d if Phone_Risk is LOW AND Privacy_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r17d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 17e if Phone_Risk is LOW AND Privacy_Risk LOW, then output is NULL;
    add_system_rule(system, "r17e", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[LOW_RISK] ))
                        )
        )

#For file operations


    #rule 18 if Phone_Risk is HIGH AND Exploit_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r18", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] ))
                        )
        )    

    #rule 18a if Phone_Risk is HIGH AND Exploit_Risk LOW, then output is HIGH;
    add_system_rule(system, "r18a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 18b if Phone_Risk is AVERAGE AND Exploit_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r18b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 18c if Phone_Risk is AVERAGE AND Exploit_Risk LOW, then output is AVERAGE;
    add_system_rule(system, "r18c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )


    #rule 18d if Phone_Risk is LOW AND Exploit_Risk LOW, then output is NULL;
    add_system_rule(system, "r18d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[LOW_RISK] ))
                        )
        )

#For dynamic operations

    #rule 19 if Phone_Risk is HIGH AND Dynamic_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r19", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] ))
                        )
        )    

    #rule 19a if Phone_Risk is HIGH AND Dynamic_Risk LOW, then output is HIGH;
    add_system_rule(system, "r19a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 19b if Phone_Risk is AVERAGE AND Dynamic_Risk HIGH, then output is HIGH;
    add_system_rule(system, "r19b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 19c if Phone_Risk is AVERAGE AND Dynamic_Risk LOW, then output is AVERAGE;
    add_system_rule(system, "r19c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[AVERAGE_RISK] ))
                        )
        )

    #rule 19d if Phone_Risk is LOW AND Dynamic_Risk HIGH, then output is AVERAGE;
    add_system_rule(system, "r19d", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[LOW_RISK] ))
                        )
        )

    #rule 19e if Phone_Risk is LOW AND Dynamic_Risk LOW, then output is NULL;
    add_system_rule(system, "r19e", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[LOW_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Phone_Risk"].adjectives[LOW_RISK] ))
                        )
        )

#For leverage Money and Privacy risks;

    #rule 20 if Privacy_Risk is HIGH AND Dynamic_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r20", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 20a if Privacy_Risk is HIGH AND Exploit_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r20a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 20b if Privacy_Risk is HIGH AND Encrypted_Code_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r20b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Encrypted_Code_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 20c if Privacy_Risk is HIGH AND Binary_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r20c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Binary_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 21 if Money_Risk is HIGH AND Dynamic_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r21", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 21a if Money_Risk is HIGH AND Exploit_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r21a", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Exploit_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 21b if Money_Risk is HIGH AND Encrypted_Code_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r21b", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Encrypted_Code_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ))
                        )
        )

    #rule 21c if Money_Risk is HIGH AND Binary_Risk HIGH, then output is UNACCEPTABLE;
    add_system_rule(system, "r21c", fuzzy.Rule.Rule(
                                            adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                            operator=fuzzy.operator.Compound.Compound(
                                                fuzzy.norm.Min.Min(),
                                                fuzzy.operator.Input.Input( system.variables["input_Binary_Risk"].adjectives[HIGH_RISK] ),
                                                fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[HIGH_RISK] ))
                        )
        )




 
    return system




SYSTEM = None
class activityRisk :
	
	def __init__(self): 
            global SYSTEM
            if SYSTEM == None :
                SYSTEM = create_system_risk()
	
	def CountingRisk(self, apkName, activity, numbers, urls, filenames) :
	
		if activity is None :
			raise Exception(FUNC() +": argument must not be None")
                file_name=  apkName + '.txt'
                output = open(file_name, 'a')
                risks = {
                    GENERAL_RISK          : 0.0,    
                    MONEY_RISK            : 0.0,
                    SMS_RISK              : 0.0,
                    PRIVACY_RISK          : 0.0,
                    INTERNET_RISK         : 0.0,
                    BINARY_RISK           : 0.0,
                    DYNAMIC_RISK          : 0.0,
                    PHONE_RISK            : 0.0,
                    EXPLOIT_RISK          : 0.0,
                    ENCRYPTED_CODE_RISK   : 0.0,
                    MALWARE_RISK          : 0.0
                    }    
        
                keys = activity.keys()
                
                for key in keys:
                    temp = activity[ key ]
                    try:
                        if key == 'FILE_READ' : 
                            risks[ PRIVACY_RISK ] += risk_values_calculate[ PRIVACY_RISK ] * len(activity['FILE_READ'])
                            risks[ EXPLOIT_RISK ] += risk_values_calculate[ EXPLOIT_RISK ] * len(activity['FILE_READ'])
                            risks[ PHONE_RISK ] += risk_values_calculate[ PHONE_RISK ] * len(activity['FILE_READ'])
		
                        if key == 'FILE_WRITE' : 
                            risks[ EXPLOIT_RISK ] += risk_values_calculate[ EXPLOIT_RISK ] * len(activity['FILE_WRITE'])
                            risks[ PHONE_RISK ] += risk_values_calculate[ PHONE_RISK ] * len(activity['FILE_WRITE'])

                        if key == 'FILE_LEAKAGE' :
                            risks[ BINARY_RISK ] += risk_values_calculate[ BINARY_RISK ] * len(activity['FILE_LEAKAGE'])
                            risks[ PRIVACY_RISK ] += risk_values_calculate[ PRIVACY_RISK ] * len(activity['FILE_LEAKAGE'])
                           
                        if key == 'CRYPTO_API':
                            risks[ ENCRYPTED_CODE_RISK ] += risk_values_calculate[ ENCRYPTED_CODE_RISK ] * len(activity['CRYPTO_API'])

                        if key == 'OPEN_CONN' :
                            risks[ INTERNET_RISK ] += risk_values_calculate[ INTERNET_RISK ] * len(activity['OPEN_CONN'])

                        if key == 'OUTGOING_TRAF' :
                            risks[ INTERNET_RISK ] += risk_values_calculate[ INTERNET_RISK ] * len(activity['OUTGOING_TRAF'])
                            risks[ MONEY_RISK ] += risk_values_calculate[ MONEY_RISK ] * len(activity['OUTGOING_TRAF'])

                        if key == 'INCOMING_TRAF' :
                            risks[ INTERNET_RISK ] += risk_values_calculate[ INTERNET_RISK ] * len(activity['INCOMING_TRAF'])
                            risks[ MONEY_RISK ] += risk_values_calculate[ MONEY_RISK ] * len(activity['INCOMING_TRAF'])
                            risks[ PHONE_RISK ] += risk_values_calculate[ PHONE_RISK ] * len(activity['INCOMING_TRAF'])
	
                        if key == 'INTERNET_LEAKAGE' :
                            risks[ INTERNET_RISK ] += risk_values_calculate[ INTERNET_RISK ] * len(activity['INTERNET_LEAKAGE'])
                            risks[ MONEY_RISK ] += risk_values_calculate[ MONEY_RISK ] * len(activity['INTERNET_LEAKAGE'])
                            risks[ PRIVACY_RISK ] += risk_values_calculate[ PRIVACY_RISK ] * len(activity['INTERNET_LEAKAGE'])
	
                        if key == 'DEX_CLASS_LOADER' :
                            risks[ DYNAMIC_RISK ] += risk_values_calculate[ DYNAMIC_RISK ] * len(activity['DEX_CLASS_LOADER'])
                            risks[ BINARY_RISK ] += risk_values_calculate[ BINARY_RISK ] * len(activity['DEX_CLASS_LOADER'])
    
                        if key == 'BROADCAST_RECEIVER' :
                            risks[ DYNAMIC_RISK ] += risk_values_calculate[ DYNAMIC_RISK ] * len(activity['BROADCAST_RECEIVER'])

                        if key == 'START_SERVICE' :
                            risks[ DYNAMIC_RISK ] += risk_values_calculate[ DYNAMIC_RISK ] * len(activity['START_SERVICE'])
                            risks[ PHONE_RISK ] += risk_values_calculate[ PHONE_RISK ] * len(activity['START_SERVICE'])
                            
                        if key == 'ENFORCED_PERMISSION' : 
                            risks[ DYNAMIC_RISK ] += risk_values_calculate[ DYNAMIC_RISK ] * len(activity['ENFORCED_PERMISSION'])
			
                        if key == 'BYPASSED_PERMISSION' : 
                            risks[ DYNAMIC_RISK ] += risk_values_calculate[ DYNAMIC_RISK ] * len(activity['BYPASSED_PERMISSION'])
                            risks[ PHONE_RISK ] += risk_values_calculate[ PHONE_RISK ] * len(activity['BYPASSED_PERMISSION'])
                         
                        if key == 'INFO_LEAKAGE_SMS' :
                            risks[ SMS_RISK ] += risk_values_calculate[ SMS_RISK ] * len(activity['INFO_LEAKAGE_SMS'])
                            risks[ PRIVACY_RISK ] += risk_values_calculate[ PRIVACY_RISK ] * len(activity['INFO_LEAKAGE_SMS'])
                      

                        if key == 'INFO_LEAKAGE_OTHERS' :
                            risks[ PHONE_RISK ] += risk_values_calculate[ PHONE_RISK ] * len(activity['INFO_LEAKAGE_OTHERS'])
                            risks[ PRIVACY_RISK ] += risk_values_calculate[ PRIVACY_RISK ] * len(activity['INFO_LEAKAGE_OTHERS'])
                        

                        if key == 'SENT_SMS_LEAKAGE' :
                            risks[ MONEY_RISK ] += risk_values_calculate[ MONEY_RISK ] * len(activity['SENT_SMS_LEAKAGE'])
                            risks[ PRIVACY_RISK ] += risk_values_calculate[ PRIVACY_RISK ] * len(activity['SENT_SMS_LEAKAGE'])
                            risks[ SMS_RISK ] += risk_values_calculate[ SMS_RISK ] * len(activity['SENT_SMS_LEAKAGE'])
	
                        if key == 'SENT_SMS_NORMAL' :
                            risks[ MONEY_RISK ] += risk_values_calculate[ MONEY_RISK ] * len(activity['SENT_SMS_NORMAL'])
                            risks[ SMS_RISK ] += risk_values_calculate[ SMS_RISK ] * len(activity['SENT_SMS_NORMAL'])
                        
                        if key == 'PHONE_CALLS' :
                            risks[ MONEY_RISK ] += risk_values_calculate[ MONEY_RISK ] * len(activity['PHONE_CALLS'])


                    except ValueError:
                        pass
                    except KeyError:
                        pass
                output_values = {"output_malware_risk" : 0.0}
                map_risks = {}
                map_risks['input_Money_Risk'] = risks[ MONEY_RISK ]
                map_risks['input_Privacy_Risk'] = risks[ PRIVACY_RISK ]
                map_risks['input_Binary_Risk'] = risks[ BINARY_RISK ]
                map_risks['input_Internet_Risk'] = risks[ INTERNET_RISK ]
                map_risks['input_Dynamic_Risk'] = risks[ DYNAMIC_RISK ]
                map_risks['input_SMS_Risk'] = risks[ SMS_RISK ]
                map_risks['input_Phone_Risk'] = risks[ PHONE_RISK ]
                map_risks['input_Encrypted_Code_Risk'] = risks[ ENCRYPTED_CODE_RISK ]
                map_risks['input_Exploit_Risk'] = risks[ EXPLOIT_RISK ]        

                SYSTEM.calculate(input = map_risks, output = output_values)
                val = output_values[ "output_malware_risk" ]


                output.write("Total score is %s\n\n" % val )
               


                
                
 

                output.write("detailed risk is :\n{ \n")
               
                temp_num = []
                key2s = map_risks.keys()
                for key2 in key2s:
                    temp = map_risks[ key2 ]
                    try:
                       output.write("\t%s :\t\t %s " % ( key2, temp ) + "\n")
                       temp_num.append(temp)
                    except ValueError:
                        pass
                    except KeyError:
                        pass
                output.write("}\n\n")

                with open('risk_scores.csv', 'a') as f:
                    writer = csv.writer(f,dialect='excel')
                    writer.writerow([apkName]+[val])

               
                with open("result.csv", 'a') as re:
                    result = csv.writer(re,dialect='excel')

                    result.writerow(('ApkName',[apkName],'Risk',[val],'Binary_risk',temp_num[0],'Internet_risk',temp_num[1],'Dynamic_risk',temp_num[2],'Exploit_risk',temp_num[3],'Phone_risk',temp_num[4],'SMS',temp_num[5],'Money_risk',temp_num[6],'Encrypted_code_risk',temp_num[7],'Privacy_risk',temp_num[8]))



                

#                phon = open("pho_num.txt",'a')
                for key in numbers:
                    try:
                        output.write("phone numbers: %s \n" % key)
#                        phon.write("%s,\t%s" % (apkName, key)+"\n")
                        with open("phone_num.csv",'a') as ph:
                            ph = csv.writer(ph,dialect='excel')
                            ph.writerow((apkName,key))
                        
                    except ValueError:
                        pass
                    except KeyError:
                        pass

                

#                ur= open("ur.txt",'a')
                for key in urls:
                    try:
                        output.write("URLs : %s \n" % key)
#                        ur.write("%s,\t%s" % (apkName,key)+"\n")
                        with open("url.csv",'a') as url:
                            url = csv.writer(url,dialect='excel')
                            url.writerow((apkName,key))
                       
                    except ValueError:
                        pass
                    except KeyError:
                        pass
                    
                for key in filenames:
                    try:
                        output.write("file names : %s \n" % key)
                    except ValueError:
                        pass
                    except KeyError:
                        pass
                output.close()
               # ur.close()
               # phon.close()
#                result.close()
#        writer.close()
                return val                   

      

   
