# JCOSTestKit
JCOS testing kit platform with modular plugin capability.

### Plugin Repository
All plugins can be found in the `plugins-repo` folder. They are in Eclipse project format but you can copy them into your own project/IDE of preference via it's source code.

### Loading Plugins
Create a `ext` folder in your working directory if it does not exist. Copy all necessary Java class `.class` files into the `ext` folder according to their package format.

### Running the JCOSTestKit platform
The executable JAR file is found in the `deliverables` folder. You should copy it out to your working directory together with the `ext` folder and start the JAR file with `java -jar JCOSTestKit.jar`. It will automatically comb the `ext` directory for all the necessary plugins and populate the platform with a list of loaded plugins for testing executions.

### Developing Plugins
Copy the `interfaces` package from the sample plugin package `DefaultJCOSTestPlugin` source folder into your own project.

Create a class that implements the `TestFunctionInterface` class and implement the necessary methods.

Compile your source codes with Oracle Java SDK compiler and copy the generated `bin` folder class files and packages into the `ext` folder of the JCOSTestKit platform. The sample plugin package already contains a fully compiled, ready and running sample code. The platform itself is also by default equipped with the sample plugin package classes ready for demo use.

### Contributing Plugins

Please issue a pull request for pulling your plugin extension packages that you want to contribute to the test extensions or to improve on the usage and capabilities of the testing framework.


