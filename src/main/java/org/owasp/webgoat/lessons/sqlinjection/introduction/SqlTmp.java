package org.owasp.webgoat.lessons.sqlinjection.introduction;

import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;

@RestController
public class SqlTmp {

    @PostMapping("/SqlInjection/attack5")
    @ResponseBody
    public AttackResult completed(@RequestParam String query) {
        return injectableQuery(query);
    }

    protected AttackResult injectableQuery(String query) {
        try (var connection = dataSource.getConnection()) {
            Statement statement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
            ResultSet results = statement.executeQuery(query);
            StringBuilder output = new StringBuilder();

            results.first();

            if (results.getString("department").equals("Marketing")) {
                output.append("<span class='feedback-positive'>" + query + "</span>");
                output.append(SqlInjectionLesson8.generateTable(results));
                return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
            } else {
                return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
            }
        } catch (SQLException sqle) {
            return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
        }
    }
}
