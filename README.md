# WSO2 Custom Grant Type
 
> A Custom Grant Type for WSO2 Identity Server that only allow one device to be used per user. This grant type validates the UUID parameter sent by the client application against the user's saved UUID and only issue an token if both the UUIDs matches.

## Build Setup

* Navigate to the project root directory and execute the following.
``` bash
  mvn clean install
```
* Navigate to the `/target` folder in the project directory and copy and paste the `WSO2-Custom-Grant-Type-1.0-SNAPSHOT` to `IS_HOME/repository/components/lib`

* Navigate to `IS_HOME/repository/conf/identity` and open the **identity.xml** file and add the following lines.
- To configure the Custom Grant type as a new grant type in WSO2 Identity Server. Add the following configuration under **<SupportedGrantTypes>**
```
<SupportedGrantType>
    <GrantTypeName>CustomGrantHandler</GrantTypeName>
    <GrantTypeHandlerImplClass>org.wso2.sample.custom.grant.type.CustomGrantHandler</GrantTypeHandlerImplClass>
    <GrantTypeValidatorImplClass>org.wso2.sample.custom.grant.type.CustomGrantValidator</GrantTypeValidatorImplClass>
    <IdTokenAllowed>true</IdTokenAllowed>
</SupportedGrantType>
``` 
 - To define the name of the **parameter** name of the UUID sent in the request and the **claim URI** the claim the UUID should be saved in.
```
<SingleDeviceConfigs claimURI="http://wso2.org/claims/organization" clientParameter="uuidClient"></SingleDeviceConfigs>
``` 
* Save the file.

* Start the WSO2 IS server to observe the changes.
